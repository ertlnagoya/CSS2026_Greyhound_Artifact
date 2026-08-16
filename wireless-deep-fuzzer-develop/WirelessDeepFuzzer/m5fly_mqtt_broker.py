
import os
import sys
import socket
import threading
import termios
import tty
import select
from time import time
import json
from colorama import Fore, Back, Style
from colorama import init as colorama_init
import errno
from enum import Enum

from scapy.all import Raw
from scapy.compat import raw
from scapy.utils import wrpcap
from scapy.layers.dot11 import RadioTap, Dot11
from scapy.layers.l2 import LLC, SNAP
from scapy.layers.inet import IP, TCP
from scapy.contrib.mqtt import MQTT, MQTTConnack, MQTTPuback, MQTTPubrec, MQTTPubrel,\
    MQTTPubcomp, MQTTSuback, MQTTUnsuback, MQTTPublish, MQTTConnect, MQTTSubscribe, MQTTUnsubscribe

import greyhound.fuzzing as fuzzing
from greyhound.fuzzing import StateConfig, MutatorRandom, SelectorRandom, SelectorAll
import greyhound.fitness as fitness
from greyhound.webserver import send_vulnerability, send_fitness, SetFuzzerConfig
from greyhound.machine import GreyhoundStateMachine


TIMEOUT_SEC = 1000  # timeout [sec]
MQTT_PUBLISH_QOS = 2

# --------------------- Machine state and transitions ------------------------------------------
states = [
    {'name': 'INIT'},
    {'name': 'DISCONNECTED'   , 'on_enter': 'iteration'},
    {'name': 'RCV_CONNECT'    , 'on_enter': 'send_connack'},
    {'name': 'CONNECTED'      , 'timeout': TIMEOUT_SEC, 'on_timeout': ['report_timeout', 'timeout_max']},
    {'name': 'RCV_PUBLISH'    , 'on_enter': ['send_pubrec'  , 'transition']},
    {'name': 'RCV_PUBREL'     , 'on_enter': ['send_pubcomp' , 'transition'], 'timeout': 2, 'on_timeout': ['report_timeout', 'timeout_max']},
    {'name': 'WAIT_PUBREC'    , 'on_enter': ['send_publish' , 'transition'], 'timeout': 2, 'on_timeout': ['report_timeout', 'timeout_max']},
    {'name': 'RCV_PUBREC'     , 'on_enter': ['send_pubrel'  , 'transition'], 'timeout': 2, 'on_timeout': ['report_timeout', 'timeout_max']},
    {'name': 'RCV_SUBSCRIBE'  , 'on_enter': ['send_suback'  , 'transition']},
    {'name': 'RCV_UNSUBSCRIBE', 'on_enter': ['send_unsuback', 'transition']},
    {'name': 'RCV_PINGREQ'    , 'on_enter': ['send_pingresp', 'transition']},
]


# State transition definition
transitions = [
    # init
    {'trigger'   : 'init',
     'source'    : 'INIT',
     'dest'      : 'DISCONNECTED'},

    # DISCONNECTED -> RCV_CONNECT
    {'trigger'   : 'update',
     'source'    : 'DISCONNECTED',
     'dest'      : 'RCV_CONNECT',
     'conditions': 'received_connect',
     'after'     : 'update'},  # Transition Action

    # RCV_CONNECT -> CONNECTED
    {'trigger'   : 'update',
     'source'    : 'RCV_CONNECT',
     'dest'      : 'CONNECTED'},

    # CONNECTED -> WAIT_PUBREC
    {'trigger'   : 'broker_publish',
     'source'    : 'CONNECTED',
     'dest'      : 'WAIT_PUBREC',
     'conditions': 'subscribed'},  # Transition Action

    # Handle broker_publish from DISCONNECTED state (ignore or stay in same state)
    {'trigger'   : 'broker_publish',
     'source'    : 'DISCONNECTED',
     'dest'      : 'DISCONNECTED'},

    # WAIT_PUBREC -> RCV_PUBREC
    {'trigger'   : 'update',
     'source'    : 'WAIT_PUBREC',
     'dest'      : 'RCV_PUBREC',
     'conditions': 'received_pubrec'},  # Transition Action

    # WAIT_PUBREC -> DISCONNECTED
    {'trigger'   : 'receive_disconnect',
     'source'    : 'WAIT_PUBREC',
     'dest'      : 'DISCONNECTED',
     'conditions': 'received_disconnect_in_wait_pubrec'},  # Transition Action

    # RCV_PUBREC -> CONNECTED
    {'trigger'   : 'update',
     'source'    : 'RCV_PUBREC',
     'dest'      : 'CONNECTED',
     'conditions': 'received_pubcomp'},  # Transition Action

    # RCV_PUBCOMP -> CONNECTED
    {'trigger'   : 'update',
     'source'    : 'RCV_PUBCOMP',
     'dest'      : 'CONNECTED'},

    # CONNECTED -> RCV_PUBLISH
    {'trigger'   : 'receive_publish',
     'source'    : 'CONNECTED',
     'dest'      : 'RCV_PUBLISH'},
    
    # RCV_PUBLISH -> RCV_PUBREL
    {'trigger'   : 'update',
     'source'    : 'RCV_PUBLISH',
     'dest'      : 'RCV_PUBREL',
     'conditions': 'received_pubrel',
     'after'     : 'update'},  # Transition Action

    # RCV_PUBREL -> CONNECTED
    {'trigger'   : 'update',
     'source'    : 'RCV_PUBREL',
     'dest'      : 'CONNECTED'},

    # CONNECTED -> RCV_SUBSCRIBE
    {'trigger'   : 'receive_subscribe',
     'source'    : 'CONNECTED',
     'dest'      : 'RCV_SUBSCRIBE',
     'after'     : 'update'},  # Transition Action

    # RCV_SUBSCRIBE -> CONNECTED
    {'trigger'   : 'update',
     'source'    : 'RCV_SUBSCRIBE',
     'dest'      : 'CONNECTED'},

    # CONNECTED -> RCV_UNSUBSCRIBE
    {'trigger'   : 'receive_unsubscribe',
     'source'    : 'CONNECTED',
     'dest'      : 'RCV_UNSUBSCRIBE',
     'after'     : 'update'},  # Transition Action

    # RCV_UNSUBSCRIBE -> CONNECTED
    {'trigger'   : 'update',
     'source'    : 'RCV_UNSUBSCRIBE',
     'dest'      : 'CONNECTED'},

    # CONNECTED -> RCV_PINGREQ
    {'trigger'   : 'receive_pingreq',
     'source'    : 'CONNECTED',
     'dest'      : 'RCV_PINGREQ',
     'after'     : 'update'},  # Transition Action

    # RCV_PINGREQ -> CONNECTED
    {'trigger'   : 'update',
     'source'    : 'RCV_PINGREQ',
     'dest'      : 'CONNECTED'},

    # CONNECTED -> DISCONNECTED
    {'trigger'   : 'receive_disconnect',
     'source'    : 'CONNECTED',
     'dest'      : 'DISCONNECTED'},

    # Timeout
    {'trigger'   : 'timeout_max',
     'source'    : ['CONNECTED', 'WAIT_PUBREC', 'RCV_PUBREC', 'RCV_PUBREL'],
     'dest'      : 'DISCONNECTED'},
]


states_fuzzer_config = {
    'DISCONNECTED': StateConfig(
        states_expected=[MQTTConnect],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT, MQTTConnack],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),    
 
    'RCV_CONNECT': StateConfig(
        states_expected=[MQTTConnect],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT, MQTTConnack],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),

    'CONNECTED': StateConfig(
        states_expected=[MQTT, MQTTPublish, MQTTSubscribe, MQTTUnsubscribe],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),

    'WAIT_PUBREC': StateConfig(
        states_expected=[MQTT, MQTTPubrec],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT, MQTTPublish],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),

    'RCV_PUBREC': StateConfig(
        states_expected=[MQTTPubcomp],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT, MQTTPubrel],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),

    'RCV_PUBLISH': StateConfig(
        states_expected=[MQTTPubrel],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT, MQTTPubrec],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),

    'RCV_PUBREL': StateConfig(
        states_expected=[MQTT],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT, MQTTPubcomp],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),

    'RCV_SUBSCRIBE': StateConfig(
        states_expected=[MQTTSubscribe],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT, MQTTSuback],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),

    'RCV_UNSUBSCRIBE': StateConfig(
        states_expected=[MQTTUnsubscribe],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT, MQTTUnsuback],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15, 15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),

    'RCV_PINGREQ': StateConfig(
        states_expected=[MQTT],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[MQTT],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[15],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['type', 'len']],
        fuzzable_layers_mutators_lengths_chance=[20],    # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),
}


# --------------------- Model Implementation ------------------------------------------
class CTRL_PKT_TYPE(Enum):
    CONNECT     = 1
    CONNACK     = 2
    PUBLISH     = 3
    PUBACK      = 4
    PUBREC      = 5
    PUBREL      = 6
    PUBCOMP     = 7
    SUBSCRIBE   = 8
    SUBACK      = 9
    UNSUBSCRIBE = 10
    UNSUBACK    = 11
    PINGREQ     = 12
    PINGRESP    = 13
    DISCONNECT  = 14


UPDATE_TYPE = {
    "update"              : 0,
    "receive_pingreq"     : 1,
    "receive_subscribe"   : 2,
    "receive_unsubscribe" : 3,
    "receive_publish"     : 4,
    "broker_publish"      : 5,
    "receive_disconnect"  : 6
}


old_settings = termios.tcgetattr(sys.stdin)
tty.setcbreak(sys.stdin.fileno())
tty.setcbreak

# MQTT Broker class for fuzzing
class MQTTBroker(object):
    # State machine variables
    machine = None                            # State machine
    iterations = 0                            # Iterations number
    idle_state = None                         # Default state
    warnings = 0                              # Count warnings (at fitness())

    # Monitoring configuration
    crash_magic_word = ''                     # Word to detect crashes
    serialport_name = '/dev/ttyUSB*'          # Serial port for monitoring
    serialport_baudrate = 115200              # Serial communication speed

    # Configuration file name
    config_file = 'MQTT_broker_config.json'   # Configuration file path

    # Network and packet variables
    pkt = None                                # Current received packet
    sock = None                               # Socket for listening to client
    conn = None
    client = None                             # Client socket
    file_count = 0                            # file Counter
    msg_count = 0                             # message counter (for use Wi-Fi sequence number)
    tcp_seqnum_send = 1000                    # TCP sequence number (send)
    tcp_seqnum_recv = 5000                    # TCP sequence number (recv)

    # Broker network configuration
    host = '0.0.0.0'                          # IP address
    port = 1883                               # MQTT default port

    # 802.11 Address
    addr_rx = "ff:ff:ff:ff:ff:ff"
    addr_tx = "02:00:00:00:00:01"
    addr_bssid = "02:00:00:00:00:01"          # AP/BSSID

    # Fuzzing configuration
    enable_fuzzing = False                    # Enable packet fuzzing
    enable_duplication = None                 # Enable packet duplication

    # Runtime variables
    global_timer = None                       # Global timeout timer
    last_deauth_time = 0                      # Last disconnection time
    boot_time = time()                        # Broker start time

    # Packet processing flags
    pkt_received = False                      # Flag for received packet
    sub_received = False                      # Flag for received subscription packet

    # Debug configuration
    enable_show_packet = False                # Enable packet detail display

    # Control parameters
    roll = 0.0
    pitch = 0.0
    yaw = 0.0
    alt = 0.0
    injected_payloads = []


    def __init__(self, machine_states, machine_transitions,
                 machine_initial_state='INIT',
                 machine_show_all_transitions=False,
                 idle_state=None,
                 crash_magic_word=None,
                 serialport_name=None,
                 serialport_baudrate=None,
                 enable_fuzzing=None,
                 enable_duplication=None):
        
        self.load_config()

        # Override configuration with provided parameters
        if crash_magic_word is not None:
            self.crash_magic_word = crash_magic_word

        if serialport_name is not None:
            self.serialport_name = serialport_name

        if serialport_baudrate is not None:
            self.serialport_baudrate = serialport_baudrate

        if idle_state is not None:
            self.idle_state = idle_state

        if enable_fuzzing is not None:
            self.enable_fuzzing = enable_fuzzing

        if enable_duplication is not None:
            self.enable_duplication = enable_duplication

        # Colors autoreset
        colorama_init(autoreset=True)

        # Initialize state machine instance
        SetFuzzerConfig(states_fuzzer_config)
        self.machine = GreyhoundStateMachine(states=machine_states,
                                        transitions=machine_transitions,
                                        print_transitions=True,
                                        print_timeout=True,
                                        initial='INIT',
                                        idle_state='DISCONNECTED',
                                        show_conditions=False,
                                        show_state_attributes=False,
                                        enable_webserver=True)

        # Initialize socket for MQTT broker
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        print("MQTT Broker listening on {}:{}".format(self.host, self.port))
        print
        
        self.start_timeout('global_timer', TIMEOUT_SEC, self.global_timeout)


    def get_config(self):
        obj = {'HOST': self.host,
               'PORT': self.port,
               'EnableFuzzing': self.enable_fuzzing,
               'EnableDuplication': self.enable_duplication,
               'EnableShowPacket': self.enable_show_packet,
               }
        return json.dumps(obj, indent=4)


    def set_config(self, data):
        self.host = data['HOST']
        self.port = data['PORT']
        self.enable_fuzzing = bool(data['EnableFuzzing'])
        self.enable_duplication = bool(data['EnableDuplication'])
        self.enable_show_packet = bool(data['EnableShowPacket'])


    def save_config(self, obj):
        f = file(self.config_file, 'w')
        f.write(json.dumps(obj, indent=4))
        f.close()


    def load_config(self):
        try:
            f = file(self.config_file, 'r')
            obj = json.loads(f.read())
            f.close()
            self.set_config(obj)
            return True
        except:
            f = file(self.config_file, 'w')
            f.write(self.get_config())
            f.close()
            return False


    def global_timeout(self):
        print(Fore.YELLOW + "Global Timeout !!!")
        if self.state is not 'DISCONNECTED':
            self.machine.report_anomaly(pkt=self.pkt)
        self.client_connected = False
        self.to_DISCONNECTED()
        self.start_timeout('global_timer', TIMEOUT_SEC, self.global_timeout)


    def disable_timeout(self, timer_name):
        timer = getattr(self, timer_name)
        if timer:
            timer.cancel()
            setattr(self, timer_name, None)


    def update_timeout(self, timer_name):
        timer = getattr(self, timer_name)
        if timer:
            timer.cancel()
            self.start_timeout(timer_name, timer.interval, timer.function)


    def start_timeout(self, timer_name, seconds, callback):
        timer = threading.Timer(seconds, callback)
        setattr(self, timer_name, timer)
        timer.daemon = True
        timer.start()


    def iteration(self):
        if self.iterations > 0:
            self.last_deauth_time = self.current_timestamp()
            fitness.Transition(reset=True)
            state_transitions = fitness.TransitionLastCount
            iterationTime = fitness.Iteration()

            if fitness.IssuePeriod > 0:
                issuePeriod = fitness.IssuePeriod
            else:
                issuePeriod = float('inf')

            self.machine.save_packets()
            print(Back.WHITE + Fore.BLACK +
                  "IssueCount:" + str(fitness.IssueCounter) + ' IssuePeriod:{0:.3f}'.format(issuePeriod)
                  + ' Transitions:' + str(state_transitions) + ' IterTime:{0:.3f}'.format(
                        iterationTime) + ' TotalIssues: '
                  + str(fitness.IssuesTotalCounter))

            send_fitness(fitness.IssueCounter, issuePeriod, state_transitions, iterationTime, self.iterations,
                         fitness.IssuesTotalCounter)

        self.iterations += 1


    def transition(self):
        self.update_timeout('global_timer')
        fitness.Transition()

    # Timeout may be caused by CRASH
    def report_timeout(self):
        self.machine.report_crash()
        self.warnings += 1

    # Inject payload into outgoing MQTTPublish packet
    def inject_payload(self, payload):
        self.injected_payloads.append(payload)

    # Send MQTT packet with fuzz
    def send(self, conn, pkt):
        if len(self.injected_payloads) > 0 and pkt.haslayer(MQTTPublish):
            payload = self.injected_payloads.pop(0)
            if payload == '[config]':
                payload += 'r=%.1f,p=%.1f,y=%.1f,a=%.1f;' % (self.roll, self.pitch, self.yaw, self.alt)
            payload += ';'
            print(Fore.CYAN + "SEND INJECTED MQTTPublish ---> " + payload)
            pkt.fields['len'] += len(payload) - len(pkt[MQTTPublish].value)
            pkt[MQTTPublish].value = payload
        elif self.enable_fuzzing:
            # Perform fuzzing on the send packet if only enable fuzzing.
            fuzzing.fuzz_packet_by_layers(pkt, self.state, states_fuzzer_config, self)

        print(Fore.CYAN + "TX ---> " + pkt.summary())

        if self.enable_show_packet:
            pkt.show()

        dot11 = Dot11(type=2, subtype=0, addr1=self.addr_rx, addr2=self.addr_tx, addr3=self.addr_bssid, SC=(self.msg_count << 4) & 0xFFF0)
        self.msg_count += 1
        ip    = IP(src="192.168.43.207", dst="192.168.43.57")
        tcp   = TCP(sport=40000 + self.iterations, dport=self.port, flags="PA", seq=self.tcp_seqnum_send, ack=1)
        self.tcp_seqnum_send += len(pkt)
        self.machine.add_packets(RadioTap() / dot11 / LLC() / SNAP() / ip / tcp / Raw(load=bytes(pkt)))

        try:
            conn.send(raw(pkt))

        # If an error occurs during send(), treat it as an anomaly.
        except socket.error as e:
            if e.errno == errno.EPIPE:
                print("[WARN] Broken pipe (EPIPE)", e)  ## If the client has disconnected, sending from the server will result in a Broken pipe error.
            elif e.errno == errno.ECONNRESET:
                print("[WARN] Connection reset (ECONNRESET)", e)
            else:
                print("[ERROR] socket.error:", e)

            self.machine.report_anomaly(pkt=pkt)
            self.warnings += 1

        if self.enable_duplication:
            fuzzing.repeat_packet(self)


    # Send a CONNACK packet in response to CONNECT
    def send_connack(self):
        if self.state is 'RCV_CONNECT' and self.pkt.type is CTRL_PKT_TYPE.CONNECT.value:
            # Create send packet
            rep = MQTT(type=2, DUP=0, QOS=0, RETAIN=0, len=2)
            rep /= MQTTConnack(sessPresentFlag=0, retcode=0)

            self.send(self.conn, rep)
            print("CONNACK sent")


    # Send a PUBLISH packet
    def send_publish(self):
        if self.state is 'WAIT_PUBREC':
            # Create send packet
            rep = MQTT(type=CTRL_PKT_TYPE.PUBLISH.value, DUP=0, QOS=MQTT_PUBLISH_QOS, RETAIN=0, len=29)
            #rep /= MQTTPublish(length=9, topic="home/test", msgid=500, value="test")
            rep /= MQTTPublish(length=13, topic="drone/control", msgid=500, value="[heartbeat];")
            
            self.send(self.conn, rep)
            print("PUBLISH sent")


    # Send a PUBREC packet in response to PUBLISH
    def send_pubrec(self):
        if self.state is 'RCV_PUBLISH' and self.pkt.type is CTRL_PKT_TYPE.PUBLISH.value:
            # Create send packet
            rep = MQTT(type=CTRL_PKT_TYPE.PUBREC.value, DUP=0, QOS=1, RETAIN=0, len=2)
            rep /= MQTTPubrec(msgid = self.pkt.msgid)
            
            self.send(self.conn, rep)
            print("PUBREC sent")


    # Send a PUBREL packet in response to PUBREC
    def send_pubrel(self):
        if self.state is 'RCV_PUBREC' and self.pkt.type is CTRL_PKT_TYPE.PUBREC.value:
            # Create send packet
            rep = MQTT(type=CTRL_PKT_TYPE.PUBREL.value, DUP=0, QOS=1, RETAIN=0, len=2)
            rep /= MQTTPubrel(msgid = self.pkt.msgid)
            
            self.send(self.conn, rep)
            print("PUBREL sent")


    # Send a PUBCOMP packet in response to PUBREL
    def send_pubcomp(self):
        if self.state is 'RCV_PUBREL' and self.pkt.type is CTRL_PKT_TYPE.PUBREL.value:
            # Create send packet
            rep = MQTT(type=CTRL_PKT_TYPE.PUBCOMP.value, DUP=0, QOS=0, RETAIN=0, len=2)
            rep /= MQTTPubcomp(msgid = self.pkt.msgid)

            self.send(self.conn, rep)
            print("PUBCOMP sent")


    # Send a SUBACK packet in response to SUBSCRIBE
    def send_suback(self):
        if self.state is 'RCV_SUBSCRIBE' and self.pkt.type is CTRL_PKT_TYPE.SUBSCRIBE.value:
            # Create send packet
            rep = MQTT(type=CTRL_PKT_TYPE.SUBACK.value, DUP=0, QOS=0, RETAIN=0, len=3)
            rep /= MQTTSuback(msgid = self.pkt.msgid, retcode=0)
            
            self.send(self.conn, rep)
            print("SUBACK sent")


    # Send a UNSUBACK packet in response to UNSUBSCRIBE
    def send_unsuback(self):
        if self.state is 'RCV_UNSUBSCRIBE' and self.pkt.type is CTRL_PKT_TYPE.UNSUBSCRIBE.value:
            # Create send packet
            rep = MQTT(type=CTRL_PKT_TYPE.UNSUBACK.value, DUP=0, QOS=0, RETAIN=0, len=2)
            rep /= MQTTUnsuback(msgid = self.pkt.msgid)
            
            self.send(self.conn, rep)
            print("UNSUBACK sent")


    # Send a PINGRESP packet in response to PINGREQ
    def send_pingresp(self):
        if self.state is 'RCV_PINGREQ' and self.pkt.type is CTRL_PKT_TYPE.PINGREQ.value:
            # Create send packet
            rep = MQTT(type=CTRL_PKT_TYPE.PINGRESP.value, DUP=0, QOS=0, RETAIN=0, len=0)

            self.send(self.conn, rep)
            print("PINGRESP sent")


    def current_timestamp_us(self):
        return (time() - self.boot_time) * 1000000


    def current_timestamp(self):
        return time() - self.boot_time


    def fitness(self, pkt):
        if fitness.Validate(pkt, self.state, states_fuzzer_config):
            return True
        else:
            self.machine.report_anomaly(pkt=pkt)
            self.warnings += 1
            return True


    # Execute state machine transition based on update type
    def update_transition(self, update_type):
        if update_type is UPDATE_TYPE['update']:
            self.update()
        elif update_type is UPDATE_TYPE['receive_pingreq']:
            self.receive_pingreq()
        elif update_type is UPDATE_TYPE['receive_subscribe']:
            self.receive_subscribe()
        elif update_type is UPDATE_TYPE['receive_unsubscribe']:
            self.receive_unsubscribe()
        elif update_type is UPDATE_TYPE['receive_publish']:
            self.receive_publish()
        elif update_type is UPDATE_TYPE['broker_publish']:
            self.broker_publish()
        elif update_type is UPDATE_TYPE['receive_disconnect']:
            self.receive_disconnect()
        else:
            print("Undefined transition")


    # Check if CONNECT was received successfully
    def received_connect(self):
        if not self.pkt_received:
            return False

        if MQTTConnect in self.pkt:
            #print(Fore.YELLOW + '[!] MQTTConnect')
            return True


    # Check if SUBSCRIBE was received successfully
    def subscribed(self):
        return True
        #if MQTTConnect in self.pkt:
            #print(Fore.YELLOW + '[!] MQTTSubscribe')
            #return True


    # Check if PUBREC was received successfully
    def received_pubrec(self):
        if not self.pkt_received:
            return False

        if MQTTPubrec in self.pkt:
            #print(Fore.YELLOW + '[!] MQTTPubrec')
            return True


    # Check if PUBREL was received successfully
    def received_pubrel(self):
        if not self.pkt_received:
            return False

        if MQTTPubrel in self.pkt:
            #print(Fore.YELLOW + '[!] MQTTPubrel')
            return True


    # Check if PUBCOMP was received successfully
    def received_pubcomp(self):
        if not self.pkt_received:
            return False

        if MQTTPubcomp in self.pkt:
            #print(Fore.YELLOW + '[!] MQTTPubcomp')
            return True

    # Check if expected DISCONNECT was received in WAIT_PUBREC
    def received_disconnect_in_wait_pubrec(self):
        if not self.pkt_received:
            return False

        if MQTT in self.pkt and CTRL_PKT_TYPE(self.pkt.type) is CTRL_PKT_TYPE.DISCONNECT:
            #print(Fore.YELLOW + '[!] MQTT.DISCONNECT')
            pkt = fuzzing.last_fuzzed_packet

            # unexpected DISCONNECTED if MQTTPublish is not fuzzed
            if pkt is None or not pkt.haslayer(MQTTPublish):
                return False

            # expected DISCONNECTED if QOS is unmatched
            if pkt.fields['QOS'] != MQTT_PUBLISH_QOS:
                print('WAIT_PUBREC: MQTT.DISCONNECT due to unmatched QOS')
                return True
            return False
        return False

    # Receive packet and perform state transition
    def receive_packet(self, conn, client):
        self.client = client
        print("Connected by {}:{}".format(*client))
        print
        
        while True:
            # Send a PUBLISH message using the subscription receive flag
            if self.sub_received and self.state is 'CONNECTED':
                self.update_transition(UPDATE_TYPE['broker_publish'])
                self.sub_received = False
                continue

            data = conn.recv(2048)
            self.pkt_received = True
            
            if not data:
                print("No data packets")
                conn.close()
                break
                
            pkt = MQTT(data)
            try:
                pkt_type = CTRL_PKT_TYPE(pkt.type)
                print("{} packet received".format(pkt_type.name))
            except ValueError:
                print("Unknown MQTT packet type received: pkt.type = {}".format(pkt.type))

            dot11 = Dot11(type=2, subtype=0, addr1=self.addr_rx, addr2=self.addr_tx, addr3=self.addr_bssid, SC=(self.msg_count << 4) & 0xFFF0)
            self.msg_count += 1
            ip    = IP(src="192.168.43.57", dst="192.168.43.207")
            tcp   = TCP(sport=self.port, dport=40000 + self.iterations, flags="PA", seq=self.tcp_seqnum_recv, ack=1)
            self.tcp_seqnum_recv += len(pkt)
            self.machine.add_packets(RadioTap() / dot11 / LLC() / SNAP() / ip / tcp / Raw(load=bytes(pkt)))

            # Process the received packet
            self.pkt = pkt
            self.fitness(pkt)
            
            # Show current state
            print(Fore.BLUE + "State:" + Fore.LIGHTCYAN_EX + self.state + Fore.LIGHTCYAN_EX)
            print(Fore.CYAN + "RX <--- " + pkt.summary())

            if self.enable_show_packet:
                pkt.show()

            # Perform state transitions for each received MQTT type
            if pkt_type is CTRL_PKT_TYPE.PUBLISH:
                print('Received topic ' + pkt[MQTTPublish].topic + ': ' + pkt[MQTTPublish].value)
                update_type = UPDATE_TYPE['receive_publish']

            elif pkt_type is CTRL_PKT_TYPE.SUBSCRIBE:
                self.sub_received = True
                update_type = UPDATE_TYPE['receive_subscribe']

            elif pkt_type is CTRL_PKT_TYPE.UNSUBSCRIBE:
                update_type = UPDATE_TYPE['receive_unsubscribe']

            elif pkt_type is CTRL_PKT_TYPE.PINGREQ:
                update_type = UPDATE_TYPE['receive_pingreq']

            elif pkt_type is CTRL_PKT_TYPE.DISCONNECT:
                update_type = UPDATE_TYPE['receive_disconnect']

            else:
                update_type = UPDATE_TYPE['update']  # Default update type

            try:
                # Execute state transition
                self.update_transition(update_type)

            except:
                pass
                
            self.pkt_received = False
            print('----------------------------')

            if update_type is UPDATE_TYPE['receive_disconnect']:
                conn.close()
                break


    # Loop from the start to the end of the connection
    def serve_forever(self):
        while True:
            try:
                conn, client = self.sock.accept()
                self.conn = conn
                self.receive_packet(conn, client)

            except KeyboardInterrupt:
                print(Fore.RED + 'Model process stopped' + Fore.RESET)
                termios.tcsetattr(sys.stdin, termios.TCSANOW, old_settings)
                sys.exit()

            except Exception as other:
                print(Fore.RED + 'Some exception occured: \n' + str(other) + Fore.RESET)

class KeyboardThread(threading.Thread):

    def __init__(self, broker):
        super(KeyboardThread, self).__init__(name='keyboard-input-thread')
        self.broker = broker
        self.daemon = True
        self.start()

    def run(self):
        while True:
            if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                c = sys.stdin.read(1)
                if c== 'f':
                    new_enable_fuzzing = not self.broker.enable_fuzzing
                    print('Set enable_fuzzing: %d --> %d' % (self.broker.enable_fuzzing, new_enable_fuzzing))
                    self.broker.enable_fuzzing = new_enable_fuzzing
                elif c == 't':
                    self.broker.roll = 0.0
                    self.broker.pitch = 0.0
                    self.broker.yaw = 0.0
                    self.broker.alt = 0.0
                    print('Add [arm] payload')
                    self.broker.inject_payload('[arm]')
                elif c == 'w':
                    new_pitch = max(self.broker.pitch-0.05, -1.0)
                    print('Set pitch: %f --> %f' % (self.broker.pitch, new_pitch))
                    self.broker.pitch = new_pitch
                    self.broker.inject_payload('[config]')
                elif c == 's':
                    new_pitch = min(self.broker.pitch+0.05, 1.0)
                    print('Set pitch: %f --> %f' % (self.broker.pitch, new_pitch))
                    self.broker.pitch = new_pitch
                    self.broker.inject_payload('[config]')
                elif c == 'a':
                    new_roll = max(self.broker.roll-0.03, -1.0)
                    print('Set roll: %f --> %f' % (self.broker.roll, new_roll))
                    self.broker.roll = new_roll
                    self.broker.inject_payload('[config]')
                elif c == 'd':
                    new_roll = min(self.broker.roll+0.03, 1.0)
                    print('Set roll: %f --> %f' % (self.broker.roll, new_roll))
                    self.broker.roll = new_roll
                    self.broker.inject_payload('[config]')
                elif c == 'q':
                    new_yaw = max(self.broker.yaw-0.05, -1.0)
                    print('Set yaw: %f --> %f' % (self.broker.yaw, new_yaw))
                    self.broker.yaw = new_yaw
                    self.broker.inject_payload('[config]')
                elif c == 'e':
                    new_yaw = min(self.broker.yaw+0.05, 1.0)
                    print('Set yaw: %f --> %f' % (self.broker.yaw, new_yaw))
                    self.broker.yaw = new_yaw
                    self.broker.inject_payload('[config]')
                elif c == 'z':
                    new_alt = max(self.broker.alt-0.1, 0)
                    print('Set alt: %f --> %f' % (self.broker.alt, new_alt))
                    self.broker.alt = new_alt
                    self.broker.inject_payload('[config]')
                elif c == 'x':
                    new_alt = min(self.broker.alt+0.1, 0.5)
                    print('Set alt: %f --> %f' % (self.broker.alt, new_alt))
                    self.broker.alt = new_alt
                    self.broker.inject_payload('[config]')
                else:
                    # print('Received ' + c) #waits to get input + Return
                    pass

if __name__ == '__main__':
    broker = MQTTBroker(states, transitions,
                        machine_show_all_transitions=False,
                        idle_state='DISCONNECTED')
    kthread = KeyboardThread(broker)
    broker.init()
    broker.serve_forever()

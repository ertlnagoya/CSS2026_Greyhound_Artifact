<template>
  <q-page class="q-pa-sm row text-center">


    <div class="col-12">
      <q-btn
        flat
        color="secondary"
        aria-label="Menu"
      >
        <q-icon size="25px" v-if="stateName!=''" name="wifi" style="padding-right: 10px"></q-icon>
        {{stateName}}
      </q-btn>
      <q-btn
        glossy
        color="secondary"
        aria-label="Menu"
        @click="resetStateMachine"
        v-if="$store.state.status.connected"
      >
        <q-icon name="fas fa-angle-double-left" style="padding-right: 10px"></q-icon>
        Reset State Machine
      </q-btn>

      <!-- <q-checkbox @input="timedReload" v-model="autoReset" label="Auto testing" class="q-pa-sm row"/> -->
    </div>


    <div class="col-12">

      <div style="margin-top: 10px">
        <graph-viz :dot-data="dotData"></graph-viz>
      </div>

    </div>

<!--    <div class="col-12" style="position: fixed; bottom: 7vh">-->


<!--    </div>-->

    <q-inner-loading :showing="loading">
      <q-spinner-puff size="200px" color="red"/>
    </q-inner-loading>
  </q-page>
</template>

<style>
</style>

<script>


  import graphViz from 'components/graphViz'
  import {Notify, Loading} from 'quasar'
  import {mapState} from 'vuex';

  export default {
    name: 'PageIndex',
    data() {
      return {
        dotData: '',
        socket: undefined,
        stateName: '',
        vulnerability: [],

        loading: false
      }
    },
    components: {
      graphViz
    },

    methods: {
      resetStateMachine: function () {
        if (this.$store.state.status.connected) {
          if (this.socket != undefined) {
            this.socket.emit('Reset')
          }
        }
      },

      showAlert(msg) {
        Notify.create({
          message: msg,
          color: 'positive',
          timeout: 2000,
          icon: 'check',
          position: 'top-right',
          type: 'positive'
        })
      },

      showError(msg) {
        Notify.create({
          message: msg,
          color: 'negative',
          timeout: 2000,
          icon: 'warning',
          position: 'top-right',
          type: 'negative',
          actions: [{ icon: 'close', color: 'white' }]
        })
      },

      showInfo(msg) {
        Notify.create({
          message: msg,
          color: 'orange',
          timeout: 0,
          icon: 'warning',
          position: 'bottom-right',
          type: 'warning',
          actions: [{ icon: 'close', color: 'white' }]
        })
      },

      showCrash(msg) {
        Notify.create({
          message: msg,
          color: 'negative',
          timeout: 0,
          icon: 'warning',
          position: 'bottom-right',
          type: 'negative',
          actions: [{ icon: 'close', color: 'white' }]
        })
      },

      getStatus(callback){
        var that = this;
        this.socket.emit('Status', (status) => {
          that.$store.state.status.model_running = status;
          if (callback){
            callback(status);
          }
        });
      },

      connectToServer() {
        var that = this;
        var addr = that.$store.state.configuration.fuzzer_service_address;
        var port = that.$store.state.configuration.fuzzer_service_port;

        var socket = this.$io('http://' + addr + ':' + port);

        this.socket = socket;
        this.loading = true;


        socket.on('connect', function () {
          console.log('Connected to server');

          that.showAlert('Connected to fuzzer service');


          that.getStatus((status)=>{
            if (status==true) {
              that.socket.emit('GetFitness', (fitness) => {
                // Update model status with model status
                try {
                  var data = JSON.parse(fitness);
                  console.log(data)
                  for (var key in data) {
                    that.$store.state.status.model_status[key] = data[key];
                  }
                } catch (e) {

                }
              });

              setTimeout(()=>{ // Get boot time after 1 second
                that.socket.emit('GetBootTime', (boot_time) => {
                  that.$store.state.status.model_boot_time = boot_time;
                });
              },1000)
            }
          });


          that.loading = false;
          that.$store.state.status.connected = true;
          that.$store.state.status.socket = that.socket;
        });

        socket.on('disconnect', function () {
          console.log('Disconnected from the server');
          that.showError('Fuzzer service disconnected');
          that.vulnerability = [];
          that.loading = true;
          that.$store.state.status.connected = false;
          that.$store.state.status.model_running = false;
          // Free socket
          if (socket.namespace != undefined)
            delete socket.namespace.sockets[socket.id];
        });

        socket.on('GraphUpdate', function (data) {
          that.dotData = data.graph;
          that.stateName = data.stateName;
          that.$store.state.status.model_state = data.stateName;
          if (that.stateName == 'WPA_HANDSHAKE_COMPLETE') {
            that.showAlert('Client Connected');
          }
        });

        socket.on('Iteration', function (data) {
          for (var key in data) {
            that.$store.state.status.model_status[key] = data[key];
          }
        });

        socket.on('StateName', function (data) {
          that.stateName = data;
          that.$store.state.status.model_state = data;
        });

        socket.on('Vulnerability', function (data) {
          if (that.vulnerability[data.message] == undefined) {
            that.vulnerability[data.message] = data.code;
            if (data.error == true)
              that.showCrash(data.message);
            else
              that.showInfo(data.message);
          }
        });

        function monitor_conn_params() {

            // Check if connection parameters changed
            if ((addr != that.$store.state.configuration.fuzzer_service_address) ||
              (port != that.$store.state.configuration.fuzzer_service_port)) {
              that.socket.disconnect();
              that.connectToServer();
              return;
            }
          // Check if client is still connected
          if (that.$store.state.status.connected == true) that.getStatus(); // Update model running status

          setTimeout(monitor_conn_params, 1000);
        }

        monitor_conn_params();
      }

    },

    mounted() {
      this.connectToServer();
    }
  }
</script>

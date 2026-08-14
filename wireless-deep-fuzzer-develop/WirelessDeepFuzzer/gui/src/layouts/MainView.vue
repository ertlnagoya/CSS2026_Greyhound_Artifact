<template>
  <q-layout view="hHh Lpr fFf">
    <q-header>
      <q-toolbar
        color="primary"
        :glossy="$q.theme === 'mat'"
        :inverted="$q.theme === 'ios'"
      >
        <q-btn
          flat
          dense
          round
          @click="leftDrawerOpen = !leftDrawerOpen"
          aria-label="Menu"
          class="q-mr-sm"
        >
          <q-icon name="menu"/>
        </q-btn>
        <!------------------------------------------------ Toolbar -->
        <q-avatar>
          <img src="statics/logo.png">
        </q-avatar>
        <q-toolbar-title>
          Wi-Fi Fuzz GUI
          <div slot="subtitle">Interactive Stateful Wireless Fuzzer</div>
        </q-toolbar-title>
        <q-btn flat dense @click.native="openURL('https://www.keysight.com')">
          <q-avatar style="width: 120px; height: 42px">
            <img src="statics/keysight_logo.png">
          </q-avatar>
        </q-btn>

      </q-toolbar>
    </q-header>

    <q-drawer
      v-model="leftDrawerOpen"
      :mini="leftDrawerState"
      @mouseover="leftDrawerState = false"
      @mouseout="leftDrawerState = true"
      mini-to-overlay
      overlay
      :width="200"
      :breakpoint="500"
      show-if-above
      bordered
      content-class="bg-grey-3"
    >
      <q-scroll-area class="fit">
        <q-list
          separator
        >
          <!-- <q-header>Menu</q-header> -->
          <!------------------------------------------------ Menu items -->
          <q-item clickable v-ripple @click.native="openURL('https://asset-group.github.io/')">
            <q-item-section avatar>
              <q-icon name="school"/>
            </q-item-section>
            <q-item-section>
              <q-item-label> ASSET Group</q-item-label>
            </q-item-section>
          </q-item>

          <q-item clickable v-ripple @click.native="openOptions">
            <q-item-section avatar>
              <q-icon name="fas fa-cog"/>
            </q-item-section>
            <q-item-section>
            <q-item-label> Options</q-item-label>
            </q-item-section>
          </q-item>

        </q-list>
      </q-scroll-area>
    </q-drawer>

    <q-page-container>
      <router-view/>
    </q-page-container>
    <!-- ----------------------------- Footer ---------------------------------->
    <q-footer>
      <q-toolbar>
        <q-toolbar-title>
          <q-chip v-if="$store.state.status.connected==false" color="red" text-color="white" icon="fas fa-times"
                  label="Disconnected"/>
          <q-chip v-else color="green" text-color="white" icon="fas fa-check"
                  label="Connected"/>
        </q-toolbar-title>
        <div v-if="$store.state.status.connected==false">
          <q-chip
            square
            dense
            color="white"
            style="margin-right: 10px"
          >
            Waiting server...
          </q-chip>
        <q-spinner color="white" size="38px"/>
        </div>
        <div v-else class="q-gutter-sm">
          <span v-if="$store.state.status.model_running">
            <q-chip
              square
              dense
              icon="fas fa-clock"
              color="white"
            >
              Running Time: {{running_time}}
            </q-chip>

            <q-chip
              square
              dense
              icon="fas fa-sync-alt"
              color="white"
            >
              Iterations: {{$store.state.status.model_status.Iteration}}
            </q-chip>

            <q-chip
              square
              dense
              icon="fas fa-exclamation-triangle"
              color="white"
            >
              Anomalies: {{$store.state.status.model_status.IssueCount}}
            </q-chip>
          </span>

          <q-btn
            @click="openModelOptions"
            push
            icon-right="fas fa-project-diagram"
            label="Model Options"
            color="secondary"/>
        </div>

      </q-toolbar>
    </q-footer>

    <!-------------------------------- MODALS --------------------------- -->
    <q-dialog v-model="modalOptions" persistent transition-show="scale" transition-hide="scale">
      <q-layout view="Lhh lpR fff" container class="bg-white">
        <q-header class="bg-primary">
          <q-toolbar>
            <q-avatar>
              <q-icon name="fas fa-cog"/>
            </q-avatar>
            <q-toolbar-title>Options</q-toolbar-title>
            <q-btn flat v-close-popup round dense icon="close"/>
          </q-toolbar>
        </q-header>

        <q-page-container>
          <q-page padding>
            <div class="q-gutter-y-md column">

              <q-input dense standout v-model="config.fuzzer_service_address" prefix="Fuzzer address:">
                <template v-slot:prepend>
                  <q-icon name="fas fa-globe-americas"/>
                </template>
              </q-input>

              <q-input dense standout v-model="config.fuzzer_service_port" prefix="Fuzzer port:">
                <template v-slot:prepend>
                  <q-icon name="web_asset"/>
                </template>
              </q-input>

              <div class="text-center q-pa-md q-gutter-sm">
                <q-btn
                  dense
                  color="primary"
                  v-close-popup
                  label="Cancel"
                  style="width: 48%"
                />
                <q-btn
                  dense
                  color="secondary"
                  @click="saveOptions"
                  label="Save"
                  style="width: 48%"
                />
              </div>

            </div>
          </q-page>
        </q-page-container>
      </q-layout>
    </q-dialog>
    <!-- ---------------------------- Model Config Modal ------------------------------------- -->
    <q-dialog v-model="modalModel" persistent transition-show="scale" transition-hide="scale">
      <q-layout view="Lhh lpR fff" container class="bg-white">
        <q-header class="bg-primary">
          <q-toolbar>
            <q-avatar>
              <q-icon name="fas fa-project-diagram"/>
            </q-avatar>
            <q-toolbar-title>Options</q-toolbar-title>
            <q-btn flat v-close-popup round dense icon="close"/>
          </q-toolbar>
        </q-header>

        <q-page-container>
          <q-page padding>
<!--            <div class="column">-->
            <div class="q-gutter-y-sm column">
              <div v-for="(value, property) in model_options">
                <q-input v-if="typeof value !== 'boolean'" dense standout v-model="model_options[property]" :label="property" />
                <q-checkbox v-else v-model="model_options[property]" :label="'Enable ' + property"/>
              </div>

              <div class="text-center q-pa-md q-gutter-sm">
                <q-btn
                  dense
                  color="primary"
                  v-close-popup
                  label="Cancel"
                  style="width: 48%"
                />
                <q-btn
                  dense
                  color="secondary"
                  @click="saveModelOptions"
                  label="Save"
                  style="width: 48%"
                />
              </div>

            </div>
          </q-page>
        </q-page-container>
      </q-layout>
    </q-dialog>

    <!-- ----------------------------------------------------------------- -->
  </q-layout>
</template>

<script>
  import {openURL} from 'quasar'
  import moment from 'moment';


  export default {
    name: 'MainView',
    data() {
      return {
        leftDrawerOpen: false,
        leftDrawerState: true,
        modalOptions: false,
        modalModel: false,
        config: {}, // Copy of UI options
        model_options:{}, //Copy of model options,
        model_status:{},
        running_time: 'NaN'
      }
    },

    methods: {
      openURL,
      openOptions() {
        this.config = Object.assign({}, this.$store.state.configuration);
        this.modalOptions = true;
      },
      saveOptions() {
        Object.assign(this.$store.state.configuration, this.config);
        this.modalOptions = false;
      },
      // Get configuration form the protocol model
      openModelOptions() {
        var that = this;
        this.$store.state.status.socket.emit('GetModelConfig', (data) => {
          console.log(data);
          data = JSON.parse(data);
          that.model_options = Object.assign({}, data);
          this.modalModel = true;
        })
      },
      saveModelOptions() {
        this.$store.state.status.socket.emit('SetModelConfig', this.model_options);
        this.$store.state.status.model_options = Object.assign({}, this.model_options); // Save to global structure
        this.modalModel = false;
      },
      updateRunningTime() {
        if (this.$store.state.status.connected && this.$store.state.status.model_boot_time > 0) {
          var diff = (Date.now() / 1000) - (this.$store.state.status.model_boot_time);

          this.running_time = String(diff).toHHMMSS();

        }

        setTimeout(this.updateRunningTime, 1000);
      }
    },

    mounted() {
      String.prototype.toHHMMSS = function () {
        var sec_num = parseInt(this, 10); // don't forget the second param
        var hours = Math.floor(sec_num / 3600);
        var minutes = Math.floor((sec_num - (hours * 3600)) / 60);
        var seconds = sec_num - (hours * 3600) - (minutes * 60);

        if (hours < 10) {
          hours = "0" + hours;
        }
        if (minutes < 10) {
          minutes = "0" + minutes;
        }
        if (seconds < 10) {
          seconds = "0" + seconds;
        }
        return hours + ':' + minutes + ':' + seconds;
      };
      this.updateRunningTime();

      this.leftDrawerOpen = this.$q.platform.is.desktop;
    }
  }
</script>

<style>
</style>

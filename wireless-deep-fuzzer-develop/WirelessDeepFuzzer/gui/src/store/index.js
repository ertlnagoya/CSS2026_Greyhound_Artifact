import Vue from 'vue'
import Vuex from 'vuex'

Vue.use(Vuex)

// Global variables
const state = {
  configuration: {
    fuzzer_service_address: '127.0.0.1',
    fuzzer_service_port: 3000
  },
  status: {
    socket: undefined,
    connected: false,
    anomalies_count: 0,
    total_run_time: 0,
    model_options: {}, // Generic model options
    model_status: {
      IssueCount: 0,
      IssuePeriod: 0,
      Transitions: 0,
      IterTime: 0,
      Iteration: 1,
      IssueTotalCount: 0
    },
    model_state: '',
    model_running: false,
    model_boot_time: 0
  }
};


// Store initialization
export default function (/* { ssrContext } */) {

  const Store = new Vuex.Store({
    state
  });

  return Store
}

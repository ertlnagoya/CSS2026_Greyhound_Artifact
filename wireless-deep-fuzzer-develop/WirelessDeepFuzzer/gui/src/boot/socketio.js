import io from 'socket.io-client';
const Viz = require('viz.js');

export default ({ Vue }) => {
  // we add it to Vue prototype
  // so we can reference it in Vue files
  // without the need to import axios
  Vue.prototype.$io = io;

}

<template>

</template>

<script>
  const Viz = require('viz.js');
  const { Module, render }  = require('viz.js/full.render.js');
  var viz = new Viz.default({ Module, render });

    export default {
        name: "graphViz",
      template: ``,
      props: ['dotData'],
      watch: {
        dotData() {
          this.render(this.dotData);
        }
      },
      mounted() {
        // initial render (if data not undefined)
        if (this.dotData) {
          this.render(this.dotData);
        }
      },
      methods: {
        render: async function(data) {
          var svg_text = await viz.renderString(this.dotData);
          this.$el.innerHTML = svg_text.replace(/width="(.*?)".height="(.*?)"/,'width="95vw" height="80vh"');
        }
      }
    }
</script>

<style scoped>

</style>

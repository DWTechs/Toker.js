
const config =  {
  input: "build/es6/toker.js",
  output: {
    name: "toker",
    file: "build/toker.mjs",
    format: "es"
  },
  external: [
    "@dwtechs/checkard",
  ],
  plugins: []
};

export default config;

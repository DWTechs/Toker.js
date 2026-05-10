
const config =  {
  input: "build/toker.js",
  output: {
    name: "toker",
    file: "build/toker.mjs",
    format: "es"
  },
  external: [
    "@dwtechs/checkard",
    "@dwtechs/hashitaka",
  ],
  plugins: []
};

export default config;

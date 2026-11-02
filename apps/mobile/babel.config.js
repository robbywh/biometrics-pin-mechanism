module.exports = function (api) {
  api.cache(true);
  return {
    presets: ['babel-preset-expo'],
    env: {
      // SEC-055: strip console.* from release bundles.
      production: { plugins: ['transform-remove-console'] },
    },
  };
};

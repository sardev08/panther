let huskyConfig = {};

if (process.env.ENABLE_PANTHER_WEB_GIT_HOOKS) {
  huskyConfig = {
    hooks: {
      'pre-commit': 'lint-staged --config web/lint-staged.config.js',
    },
  };
}

module.exports = huskyConfig;

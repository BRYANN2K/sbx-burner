// Conventional Commits, checked on every pull request.
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', ['feat', 'fix', 'docs', 'test', 'ci', 'chore', 'refactor', 'perf', 'build', 'revert']],
    'scope-enum': [
      1,
      'always',
      ['runner', 'recipe', 'kit', 'skill', 'schema', 'lint', 'index', 'template', 'eval', 'scope', 'deps', 'ci'],
    ],
    'subject-case': [2, 'never', ['upper-case', 'pascal-case', 'start-case']],
    'header-max-length': [2, 'always', 100],
    'body-max-line-length': [1, 'always', 120],
  },
};

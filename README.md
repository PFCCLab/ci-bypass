# CI Bypass

Bypass CI checks for GitHub Actions.

This action allows some users have no maintainers permissions to bypass CI checks. It is useful for CI/CD team to bypass CI checks on some special cases.

## Usage

### Skip job

```yaml
jobs:
   check-bypass:
      name: Check Bypass
      runs-on: ubuntu-slim
      permissions:
         contents: read
      outputs:
         can-skip: ${{ steps.check-bypass.outputs.can-skip }}
      steps:
         - id: check-bypass
           name: Check Bypass
           uses: PFCCLab/ci-bypass@v2
           with:
              github-token: ${{ secrets.GITHUB_TOKEN }}
              non-pull-request-event-strategy: 'always-skipped'
              type: 'labeled'
              label: 'ci-bypass: example | ci-bypass: all'
              username: 'SigureMo'

   build:
      needs: check-bypass
      if: ${{ needs.check-bypass.outputs.can-skip != 'true' }}
      name: Build
      runs-on: ubuntu-latest

      steps:
         - name: Run build
           run: echo "Run build"
```

### Skip steps

```yaml
permissions:
   contents: read
jobs:
   build:
      name: Build
      runs-on: ubuntu-latest

      steps:
         - id: check-bypass
           name: Check Bypass
           uses: PFCCLab/ci-bypass@v2
           with:
              github-token: ${{ secrets.GITHUB_TOKEN }}
              non-pull-request-event-strategy: 'always-skipped'
              type: 'labeled'
              label: 'ci-bypass: example | ci-bypass: all'
              username: 'SigureMo'
         - name: Run build
           if: ${{ steps.check-bypass.outputs.can-skip != 'true' }}
           run: echo "Run build"
```

### Skip with composite rule

```yaml
permissions:
   contents: read
jobs:
   build:
      name: Build
      runs-on: ubuntu-latest

      steps:
         - id: check-bypass
           name: Check Bypass
           uses: PFCCLab/ci-bypass@v2
           with:
              github-token: ${{ secrets.GITHUB_TOKEN }}
              non-pull-request-event-strategy: 'always-skipped'
              type: 'composite'
              composite-rule: |
                 {
                    "any": [
                       {
                          "type": "labeled",
                          "label": ["ci-bypass: example", "ci-bypass: all"],
                          "username": ["SigureMo"]
                       },
                       {
                          "type": "commented",
                          "comment-pattern": [".*/bypass example.*", ".*/bypass all.*"],
                          "username": ["SigureMo"]
                       },
                       {
                          "type": "approved",
                          "username": ["SigureMo", "gouzil"]
                       }
                    ]
                 }
         - name: Run build
           if: ${{ steps.check-bypass.outputs.can-skip != 'true' }}
           run: echo "Run build"
```

### All options

<!-- prettier-ignore -->
| Name | Description | Required | Default |
| - | - | - | - |
| `github-token` | GitHub token to access GitHub API | false | `undefined` |
| `non-pull-request-event-strategy` | Strategy to apply to non-pull-request events, can be always-skipped, never-skipped, or always-failed, default is always-failed | true | `always-failed` |
| `type` | Type of the rule, can be `labeled`, `commented`, `approved`, or `composite` | true | `labeled` |
| `username` | Username, can be a string or an array of strings separated by `\|` | false | `undefined` |
| `user-team` | User team, can be a string or an array of strings separated by `\|` | false | `undefined` |
| `label` | Label name, can be a string or an array of strings separated by `\|` | false | `undefined` |
| `comment-pattern` | Comment regex pattern, can be a string or an array of strings separated by `\|` | false | `undefined` |
| `composite-rule` | Use any, all or not to combine multiple rules, need to be a JSON string | false | `undefined` |

> [!NOTE]
>
> `user-team` needs `read:org` permission, but the default `GITHUB_TOKEN` doesn't have this permission. You need to create a personal token with `read:org` permission.

## Contributing

### Initial setup

1. Install the dependencies:

   ```bash
   pnpm install
   ```

2. Test the basic functionality:

   ```bash
   pnpm test
   ```

3. Run bundle:

   ```bash
   pnpm bundle
   ```

## Acknowledgement

- [Legorooj/skip-ci](https://github.com/Legorooj/skip-ci) - Provide a way to skip CI checks in GitHub Actions.
- [ast-grep/ast-grep](https://github.com/ast-grep/ast-grep) - Provide a interface to combine multiple rules.

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ansible.parsing.vault import EncryptedString

from ansiblelint.file_utils import Lintable
from ansiblelint.rules import AnsibleLintRule
from ansiblelint.skip_utils import get_rule_skips_from_line
from ansiblelint.utils import parse_yaml_from_file

if TYPE_CHECKING:
    from ansiblelint.errors import MatchError
    from ansiblelint.utils import Task


class SecretsCheckingRule(AnsibleLintRule):
    id = "secrets"
    severity = "MEDIUM"
    tags = ["idiom"]
    version_changed = "1.0.0"
    needs_raw_task = True
    # List of special variables that should have vaulted values
    restricted_names = {
        "password",
        "apikey"
    }

    _ids = {
        "secrets[no-vault]": "Variables containing secrets must be vaulted",
    }

    # pylint: disable=too-many-return-statements
    def get_var_naming_matcherror(
        self,
        ident: str,
        t: Any,
        *,
        file: Lintable,
    ) -> MatchError | None:
        if not isinstance(t, EncryptedString):
            if any(name in ident for name in self.restricted_names):
                return self.create_matcherror(
                    tag="secrets[no-vault]",
                    message=f" ({ident})",
                    filename=file,
                )

        return None

    def matchplay(self, file: Lintable, data: dict[str, Any]) -> list[MatchError]:
        """Return matches found for a specific playbook."""
        results: list[MatchError] = []
        raw_results: list[MatchError] = []

        if not data or file.kind not in ("tasks", "handlers", "playbook", "vars"):
            return results
        # If the Play uses the 'vars' section to set variables
        our_vars = data.get("vars")
        if not our_vars == None:
            for key, v in our_vars.items():
                match_error = self.get_var_naming_matcherror(key, v, file=file)
                if match_error:
                    match_error.message = "Playbook vars containing secrets should be vaulted" + match_error.message
                    raw_results.append(match_error)
        roles = data.get("roles", [])
        for role in roles:
            if isinstance(role, str):
                continue

            our_vars = role.get("vars", {})
            for key, v in our_vars.items():
                match_error = self.get_var_naming_matcherror(
                    key,
                    v,
                    file=file,
                )
                if match_error:
                    match_error.message = "Role vars containing secrets should be vaulted" + match_error.message
                    raw_results.append(match_error)
        if raw_results:
            lines = file.content.splitlines()
            for match in raw_results:
                # lineno starts with 1, not zero
                skip_list = get_rule_skips_from_line(
                    line=lines[match.lineno - 1],
                    lintable=file,
                )
                if match.rule.id not in skip_list and match.tag not in skip_list:
                    results.append(match)

        return results

    # def matchtask(
    #     self,
    #     task: Task,
    #     file: Lintable | None = None,
    # ) -> list[MatchError]:
    #     """Return matches for task based variables."""
    #     results = []
    #     ansible_module = task["action"]["__ansible_module__"]
    #     # If the task uses the 'vars' section to set variables
    #     # only check role prefix for include_role and import_role tasks 'vars'
    #     our_vars = task.get("vars", {})
    #     if ansible_module in ("include_role", "import_role"):
    #         action = task["action"]
    #     for key in our_vars:
    #         match_error = self.get_var_naming_matcherror(
    #             key,
    #             file=file or Lintable(""),
    #         )
    #         if match_error:
    #             match_error.message += f" (TASK)"
    #             results.append(match_error)

    #     # If the task uses the 'set_fact' module
    #     if ansible_module == "set_fact":
    #         for key in filter(
    #             lambda x: isinstance(x, str)
    #             and not x.startswith("__")
    #             and x != "cacheable",
    #             task["action"].keys(),
    #         ):
    #             match_error = self.get_var_naming_matcherror(
    #                 key,
    #                 file=file or Lintable(""),
    #             )
    #             if match_error:
    #                 match_error.lineno = task.line
    #                 match_error.message += f" (SET_FACT)"
    #                 results.append(match_error)

    #     return results

    def matchyaml(self, file: Lintable) -> list[MatchError]:
        """Return matches for variables defined in vars files."""
        results: list[MatchError] = []
        raw_results: list[MatchError] = []

        if str(file.kind) == "vars" and file.data:
            meta_data = parse_yaml_from_file(str(file.path))
            if not isinstance(meta_data, dict):
                msg = f"Content if vars file {file} is not a dictionary."
                raise TypeError(msg)
            for key, v in meta_data.items():
                match_error = self.get_var_naming_matcherror(
                    key,
                    v,
                    file=file,
                )
                if match_error:
                    match_error.message = "Secrets in vars files should be vaulted" + match_error.message
                    raw_results.append(match_error)
            if raw_results:
                lines = file.content.splitlines()
                for match in raw_results:
                    # lineno starts with 1, not zero
                    skip_list = get_rule_skips_from_line(
                        line=lines[match.lineno - 1],
                        lintable=file,
                    )
                    if match.rule.id not in skip_list and match.tag not in skip_list:
                        results.append(match)
        else:
            results.extend(super().matchyaml(file))
        return results

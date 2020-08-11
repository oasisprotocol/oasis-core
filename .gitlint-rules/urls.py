import re

import gitlint
from gitlint.rules import CommitRule, ConfigurationRule

# Monkey patch gitlint so it allows us to define a user-defined ConfigurationRule.
gitlint.rule_finder.assert_valid_rule_class = lambda *_: True

# URL regular expression.
URL_RE_RAW = r'http[s]?://(?:[a-zA-Z]|[0-9]|[#-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
URL_RE = re.compile(URL_RE_RAW, re.IGNORECASE)
LINE_MATCH_RE = re.compile(r'.*' + URL_RE_RAW + r'$')

class RemoveURLs(CommitRule, ConfigurationRule):
    """Removes all URLs from all lines."""

    name = "remove-urls"
    id = "UC1"

    def apply(self, config, commit):
        """Modify the commit message to remove all URLs."""
        if not commit.message.body:
            return

        # Skip the first line as we shouldn't have URLs in the title.
        new_body = [commit.message.body[0]]
        new_body += [
            URL_RE.sub('', line).strip() if LINE_MATCH_RE.match(line) else line
            for line in commit.message.body[1:]
        ]
        commit.message.body = new_body

    def validate(self, commit):
        """Implements CommitRule."""
        return

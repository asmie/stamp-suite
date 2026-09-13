# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit acct-user

DESCRIPTION="User for the stamp-suite STAMP reflector service"
# -1 requests dynamic allocation; a fixed ID is assigned from
# uid-gid.txt when the package enters ::gentoo.
ACCT_USER_ID=-1
ACCT_USER_GROUPS=( stamp )

acct-user_add_deps

# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit acct-group

DESCRIPTION="Group for the stamp-suite STAMP reflector service"
# -1 requests dynamic allocation; a fixed ID is assigned from
# uid-gid.txt when the package enters ::gentoo.
ACCT_GROUP_ID=-1

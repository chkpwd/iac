#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2023 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_antivirus_profile
short_description: Configure AntiVirus profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        required: false
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    antivirus_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            analytics-bl-filetype:
                type: str
                description: Only submit files matching this DLP file-pattern to FortiSandbox.
            analytics-db:
                type: str
                description: Enable/disable using the FortiSandbox signature database to supplement the AV signature databases.
                choices:
                    - 'disable'
                    - 'enable'
            analytics-max-upload:
                type: int
                description: Maximum size of files that can be uploaded to FortiSandbox
            analytics-wl-filetype:
                type: str
                description: Do not submit files matching this DLP file-pattern to FortiSandbox.
            av-block-log:
                type: str
                description: Enable/disable logging for AntiVirus file blocking.
                choices:
                    - 'disable'
                    - 'enable'
            av-virus-log:
                type: str
                description: Enable/disable AntiVirus logging.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            extended-log:
                type: str
                description: Enable/disable extended logging for antivirus.
                choices:
                    - 'disable'
                    - 'enable'
            ftgd-analytics:
                type: str
                description: Settings to control which files are uploaded to FortiSandbox.
                choices:
                    - 'disable'
                    - 'suspicious'
                    - 'everything'
            inspection-mode:
                type: str
                description: Inspection mode.
                choices:
                    - 'proxy'
                    - 'flow-based'
            mobile-malware-db:
                type: str
                description: Enable/disable using the mobile malware signature database.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Profile name.
            replacemsg-group:
                type: str
                description: Replacement message group customized for this profile.
            scan-mode:
                type: str
                description: Choose between full scan mode and quick scan mode.
                choices:
                    - 'quick'
                    - 'full'
                    - 'legacy'
                    - 'default'
            feature-set:
                type: str
                description: Flow/proxy feature set.
                choices:
                    - 'proxy'
                    - 'flow'
            cifs:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: Enable/disable CIFS AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'quarantine'
                            - 'avmonitor'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            content-disarm:
                description: no description
                type: dict
                required: false
                suboptions:
                    cover-page:
                        type: str
                        description: Enable/disable inserting a cover page into the disarmed document.
                        choices:
                            - 'disable'
                            - 'enable'
                    detect-only:
                        type: str
                        description: Enable/disable only detect disarmable files, do not alter content.
                        choices:
                            - 'disable'
                            - 'enable'
                    error-action:
                        type: str
                        description: Action to be taken if CDR engine encounters an unrecoverable error.
                        choices:
                            - 'block'
                            - 'log-only'
                            - 'ignore'
                    office-action:
                        type: str
                        description: Enable/disable stripping of PowerPoint action events in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office-dde:
                        type: str
                        description: Enable/disable stripping of Dynamic Data Exchange events in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office-embed:
                        type: str
                        description: Enable/disable stripping of embedded objects in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office-hylink:
                        type: str
                        description: Enable/disable stripping of hyperlinks in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office-linked:
                        type: str
                        description: Enable/disable stripping of linked objects in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office-macro:
                        type: str
                        description: Enable/disable stripping of macros in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    original-file-destination:
                        type: str
                        description: Destination to send original file if active content is removed.
                        choices:
                            - 'fortisandbox'
                            - 'quarantine'
                            - 'discard'
                    pdf-act-form:
                        type: str
                        description: Enable/disable stripping of PDF document actions that submit data to other targets.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-gotor:
                        type: str
                        description: Enable/disable stripping of PDF document actions that access other PDF documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-java:
                        type: str
                        description: Enable/disable stripping of PDF document actions that execute JavaScript code.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-launch:
                        type: str
                        description: Enable/disable stripping of PDF document actions that launch other applications.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-movie:
                        type: str
                        description: Enable/disable stripping of PDF document actions that play a movie.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-sound:
                        type: str
                        description: Enable/disable stripping of PDF document actions that play a sound.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-embedfile:
                        type: str
                        description: Enable/disable stripping of embedded files in PDF documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-hyperlink:
                        type: str
                        description: Enable/disable stripping of hyperlinks from PDF documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-javacode:
                        type: str
                        description: Enable/disable stripping of JavaScript code in PDF documents.
                        choices:
                            - 'disable'
                            - 'enable'
            ftp:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: Enable/disable FTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            http:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    content-disarm:
                        type: str
                        description: Enable Content Disarm and Reconstruction for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: Enable/disable HTTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                            - 'strict-file'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-optimize:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    unknown-content-encoding:
                        type: str
                        description: Configure the action the FortiGate unit will take on unknown content-encoding.
                        choices:
                            - 'block'
                            - 'inspect'
                            - 'bypass'
            imap:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    content-disarm:
                        type: str
                        description: Enable Content Disarm and Reconstruction for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        description: Enable/disable IMAP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            mapi:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        description: Enable/disable MAPI AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            nac-quar:
                description: no description
                type: dict
                required: false
                suboptions:
                    expiry:
                        type: str
                        description: Duration of quarantine.
                    infected:
                        type: str
                        description: Enable/Disable quarantining infected hosts to the banned user list.
                        choices:
                            - 'none'
                            - 'quar-src-ip'
                            - 'quar-interface'
                    log:
                        type: str
                        description: Enable/disable AntiVirus quarantine logging.
                        choices:
                            - 'disable'
                            - 'enable'
            nntp:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: Enable/disable NNTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            outbreak-prevention:
                description: no description
                type: dict
                required: false
                suboptions:
                    external-blocklist:
                        type: str
                        description: Enable/disable external malware blocklist.
                        choices:
                            - 'disable'
                            - 'enable'
                    ftgd-service:
                        type: str
                        description: Enable/disable FortiGuard Virus outbreak prevention service.
                        choices:
                            - 'disable'
                            - 'enable'
            pop3:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    content-disarm:
                        type: str
                        description: Enable Content Disarm and Reconstruction for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        description: Enable/disable POP3 AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            smtp:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    content-disarm:
                        type: str
                        description: Enable Content Disarm and Reconstruction for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        description: Enable/disable SMTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            ssh:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: Enable/disable SFTP and SCP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'avmonitor'
                            - 'quarantine'
                            - 'scan'
                    outbreak-prevention:
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            smb:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: description
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive-log:
                        description: description
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: description
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak-prevention:
                        type: str
                        description: Enable FortiGuard Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
            analytics-accept-filetype:
                type: str
                description: Only submit files matching this DLP file-pattern to FortiSandbox.
            analytics-ignore-filetype:
                type: str
                description: Do not submit files matching this DLP file-pattern to FortiSandbox.
            ems-threat-feed:
                type: str
                description: Enable/disable use of EMS threat feed when performing AntiVirus scan.
                choices:
                    - 'disable'
                    - 'enable'
            external-blocklist:
                type: str
                description: One or more external malware block lists.
            external-blocklist-archive-scan:
                type: str
                description: Enable/disable external-blocklist archive scanning.
                choices:
                    - 'disable'
                    - 'enable'
            external-blocklist-enable-all:
                type: str
                description: Enable/disable all external blocklists.
                choices:
                    - 'disable'
                    - 'enable'
            outbreak-prevention-archive-scan:
                type: str
                description: Enable/disable outbreak-prevention archive scanning.
                choices:
                    - 'disable'
                    - 'enable'
            fortindr-error-action:
                type: str
                description: Action to take if FortiNDR encounters an error.
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortindr-timeout-action:
                type: str
                description: Action to take if FortiNDR encounters a scan timeout.
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortisandbox-error-action:
                type: str
                description: Action to take if FortiSandbox inline scan encounters an error.
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortisandbox-max-upload:
                type: int
                description: Maximum size of files that can be uploaded to FortiSandbox.
            fortisandbox-mode:
                type: str
                description: FortiSandbox scan modes.
                choices:
                    - 'inline'
                    - 'analytics-suspicious'
                    - 'analytics-everything'
            fortisandbox-timeout-action:
                type: str
                description: Action to take if FortiSandbox inline scan encounters a scan timeout.
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortiai-timeout-action:
                type: str
                description: Action to take if FortiAI encounters a scan timeout.
                choices:
                    - 'block'
                    - 'log-only'
                    - 'ignore'
            fortiai-error-action:
                type: str
                description: Action to take if FortiAI encounters an error.
                choices:
                    - 'block'
                    - 'log-only'
                    - 'ignore'

'''

EXAMPLES = '''
 - name: gathering fortimanager facts
   hosts: fortimanager00
   gather_facts: no
   connection: httpapi
   collections:
     - fortinet.fortimanager
   vars:
     ansible_httpapi_use_ssl: True
     ansible_httpapi_validate_certs: False
     ansible_httpapi_port: 443
   tasks:
    - name: retrieve all the antivirus profiles
      fmgr_fact:
        facts:
            selector: 'antivirus_profile'
            params:
                adom: 'ansible'
                profile: 'your_value'
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure AntiVirus profiles.
      fmgr_antivirus_profile:
         adom: ansible
         state: present
         antivirus_profile:
            analytics-db: disable
            analytics-max-upload: 20
            av-block-log: disable
            av-virus-log: disable
            comment: 'test comment'
            extended-log: disable
            ftgd-analytics: disable
            inspection-mode: proxy
            mobile-malware-db: disable
            name: 'antivirus-profile'
            scan-mode: quick
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/antivirus/profile',
        '/pm/config/global/obj/antivirus/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}',
        '/pm/config/global/obj/antivirus/profile/{profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'antivirus_profile': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '6.4.6': True,
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '7.0.0': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'options': {
                'analytics-bl-filetype': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'analytics-db': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'analytics-max-upload': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'analytics-wl-filetype': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'av-block-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'av-virus-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'extended-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ftgd-analytics': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'suspicious',
                        'everything'
                    ],
                    'type': 'str'
                },
                'inspection-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'choices': [
                        'proxy',
                        'flow-based'
                    ],
                    'type': 'str'
                },
                'mobile-malware-db': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'replacemsg-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'scan-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'quick',
                        'full',
                        'legacy',
                        'default'
                    ],
                    'type': 'str'
                },
                'feature-set': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                },
                'cifs': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'quarantine',
                                'avmonitor'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'content-disarm': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cover-page': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'detect-only': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'error-action': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'block',
                                'log-only',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'office-action': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-dde': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-embed': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-hylink': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-linked': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-macro': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'original-file-destination': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'fortisandbox',
                                'quarantine',
                                'discard'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-form': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-gotor': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-java': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-launch': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-movie': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-sound': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-embedfile': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-hyperlink': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-javacode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'ftp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'http': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'content-disarm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor',
                                'strict-file'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-optimize': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'unknown-content-encoding': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'block',
                                'inspect',
                                'bypass'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'imap': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'content-disarm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'executables': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'default',
                                'virus'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'mapi': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'executables': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'default',
                                'virus'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'nac-quar': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'expiry': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'infected': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'none',
                                'quar-src-ip',
                                'quar-interface'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'nntp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'outbreak-prevention': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ftgd-service': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'pop3': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'content-disarm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'executables': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'default',
                                'virus'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'smtp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'content-disarm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'executables': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'default',
                                'virus'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'ssh': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'avmonitor',
                                'quarantine',
                                'scan'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': False,
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortiai': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': False,
                                '6.4.7': False,
                                '6.4.8': False,
                                '6.4.9': False,
                                '6.4.10': False,
                                '6.4.11': False,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'smb': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'analytics-accept-filetype': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'analytics-ignore-filetype': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ems-threat-feed': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'external-blocklist': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'external-blocklist-archive-scan': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'external-blocklist-enable-all': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'outbreak-prevention-archive-scan': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fortindr-error-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'log-only',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'fortindr-timeout-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'log-only',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'fortisandbox-error-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'log-only',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'fortisandbox-max-upload': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fortisandbox-mode': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'inline',
                        'analytics-suspicious',
                        'analytics-everything'
                    ],
                    'type': 'str'
                },
                'fortisandbox-timeout-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'log-only',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'fortiai-timeout-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'block',
                        'log-only',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'fortiai-error-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'block',
                        'log-only',
                        'ignore'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_profile'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('access_token', module.params['access_token'] if 'access_token' in module.params else None)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()

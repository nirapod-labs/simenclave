// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import SimEnclaveCTLKit

// The executable is a thin shell: all logic lives in SimEnclaveCTLKit so it can be
// unit-tested. The process exit code is the command's, so a script or an agent can
// branch on it.
exit(CLI.run(CommandLine.arguments))

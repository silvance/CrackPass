/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * hashcat-native status codes and their mapping to the engine-neutral
 * RecoveryState. The generic status structure lives in recoverystatus.h; this
 * header holds only the parts that are genuinely hashcat-specific (the numeric
 * codes hashcat reports in its --status-json "status" field).
 */
#ifndef FORENSIC_HASHCATSTATUS_H
#define FORENSIC_HASHCATSTATUS_H

#include "recoverystatus.h"

namespace forensic {

// hashcat status codes (from its --status-json "status" field).
namespace HashcatStatusCode {
constexpr int Running = 3;
constexpr int Paused = 4;
constexpr int Exhausted = 5;
constexpr int Cracked = 6;
constexpr int Aborted = 7;
constexpr int Quit = 8;
}

// Map a hashcat-native status code onto the engine-neutral RecoveryState.
inline RecoveryState recoveryStateFromHashcatCode(int code)
{
    switch (code) {
    case HashcatStatusCode::Running:   return RecoveryState::Running;
    case HashcatStatusCode::Paused:    return RecoveryState::Paused;
    case HashcatStatusCode::Exhausted: return RecoveryState::Exhausted;
    case HashcatStatusCode::Cracked:   return RecoveryState::Recovered;
    case HashcatStatusCode::Aborted:   return RecoveryState::Aborted;
    case HashcatStatusCode::Quit:      return RecoveryState::Quit;
    default:                           return RecoveryState::Unknown;
    }
}

} // namespace forensic

#endif // FORENSIC_HASHCATSTATUS_H

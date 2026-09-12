/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_HASHINGSERVICE_H
#define FORENSIC_HASHINGSERVICE_H

#include <QString>

namespace forensic {

/*
 * Computes cryptographic digests of source artifacts.
 *
 * Evidence integrity rule: the file is opened READ-ONLY and streamed in
 * chunks. The service never writes to, truncates, or otherwise modifies the
 * source file.
 */
class HashingService
{
public:
    // Returns the lowercase hex SHA-256 of the file, or an empty string on
    // failure (with *error populated when provided).
    static QString sha256File(const QString &path, QString *error = nullptr);

    // Chunk size used while streaming. Exposed for tests.
    static constexpr qint64 ChunkSize = 1 << 20; // 1 MiB
};

} // namespace forensic

#endif // FORENSIC_HASHINGSERVICE_H

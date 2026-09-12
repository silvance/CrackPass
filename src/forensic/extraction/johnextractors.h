/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Concrete *2john adapters, one per artifact/extractor type. Each maps a
 * single artifact type to its extraction tool and hash->mode resolution.
 */
#ifndef FORENSIC_JOHNEXTRACTORS_H
#define FORENSIC_JOHNEXTRACTORS_H

#include "john2hashextractor.h"
#include "moderesolution.h"

namespace forensic {

#define FORENSIC_JOHN_EXTRACTOR(ClassName, IdStr, NameStr, ToolStr, TypeStr, ModeFn) \
    class ClassName : public John2HashExtractor                                      \
    {                                                                                \
    public:                                                                          \
        QString id() const override { return QStringLiteral(IdStr); }                \
        QString displayName() const override { return QStringLiteral(NameStr); }     \
        QString toolId() const override { return QStringLiteral(ToolStr); }          \
        bool supports(const ArtifactType &t) const override                          \
        {                                                                            \
            return t.id == QStringLiteral(TypeStr);                                  \
        }                                                                            \
    protected:                                                                       \
        QVector<HashcatModeOption> resolveModes(const QString &hash) const override  \
        {                                                                            \
            return modes::ModeFn(hash);                                              \
        }                                                                            \
    };

FORENSIC_JOHN_EXTRACTOR(OfficeHashExtractor,   "office2john",   "Microsoft Office (office2john)", "office2john",   "ms-office",     forOffice)
FORENSIC_JOHN_EXTRACTOR(PdfHashExtractor,      "pdf2john",      "PDF (pdf2john)",                 "pdf2john",      "pdf",           forPdf)
FORENSIC_JOHN_EXTRACTOR(ZipHashExtractor,      "zip2john",      "ZIP (zip2john)",                 "zip2john",      "zip",           forZip)
FORENSIC_JOHN_EXTRACTOR(RarHashExtractor,      "rar2john",      "RAR (rar2john)",                 "rar2john",      "rar",           forRar)
FORENSIC_JOHN_EXTRACTOR(SevenZipHashExtractor, "7z2john",       "7-Zip (7z2john)",                "7z2john",       "7z",            forSevenZip)
FORENSIC_JOHN_EXTRACTOR(KeePassHashExtractor,  "keepass2john",  "KeePass (keepass2john)",         "keepass2john",  "keepass-kdbx",  forKeePass)

#undef FORENSIC_JOHN_EXTRACTOR

} // namespace forensic

#endif // FORENSIC_JOHNEXTRACTORS_H

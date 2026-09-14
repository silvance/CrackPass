/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "reportrenderer.h"

#include <QJsonDocument>

namespace forensic {

namespace {

QString esc(const QString &s)
{
    QString o = s;
    o.replace(QLatin1Char('&'), QStringLiteral("&amp;"));
    o.replace(QLatin1Char('<'), QStringLiteral("&lt;"));
    o.replace(QLatin1Char('>'), QStringLiteral("&gt;"));
    return o;
}

QString row(const QString &k, const QString &v)
{
    return QStringLiteral("<tr><th>%1</th><td>%2</td></tr>\n").arg(esc(k), esc(v.isEmpty() ? QStringLiteral("-") : v));
}

} // namespace

QByteArray ReportRenderer::toJson(const RecoveryReport &report)
{
    return QJsonDocument(report.toJson()).toJson(QJsonDocument::Indented);
}

QString ReportRenderer::toHtml(const RecoveryReport &report)
{
    const QString runtime = QStringLiteral("%1 ms").arg(report.runtimeMs);
    QString h;
    h += QStringLiteral("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
    h += QStringLiteral("<title>Recovery Report - %1</title>").arg(esc(report.artifactFilename));
    h += QStringLiteral("<style>body{font-family:sans-serif;margin:2rem;color:#111}"
                        "h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.5rem;border-bottom:1px solid #ccc}"
                        "table{border-collapse:collapse;width:100%;margin:.5rem 0}"
                        "th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}"
                        "th{background:#f5f5f5;width:16rem}.ok{color:#137333}.rec{background:#e6f4ea}"
                        "code{white-space:pre-wrap;word-break:break-all}</style></head><body>");

    h += QStringLiteral("<h1>Recovery Report</h1>");
    h += QStringLiteral("<p>Generated %1 by CaseKey %2</p>").arg(esc(report.generatedUtc), esc(report.applicationVersion));

    h += QStringLiteral("<h2>Case</h2><table>");
    h += row(QStringLiteral("Case identifier"), report.caseId);
    h += row(QStringLiteral("Case name"), report.caseName);
    h += row(QStringLiteral("Examiner"), report.examiner);
    h += QStringLiteral("</table>");

    h += QStringLiteral("<h2>Artifact</h2><table>");
    h += row(QStringLiteral("Filename"), report.artifactFilename);
    h += row(QStringLiteral("Path"), report.artifactPath);
    h += row(QStringLiteral("Size (bytes)"), QString::number(report.artifactSize));
    h += row(QStringLiteral("SHA-256"), report.artifactSha256);
    h += row(QStringLiteral("Modified (UTC)"), report.artifactModifiedUtc);
    h += row(QStringLiteral("Created (UTC)"), report.artifactCreatedUtc);
    h += row(QStringLiteral("Detected type"), report.detectedType);
    h += QStringLiteral("</table>");

    h += QStringLiteral("<h2>Extraction</h2><table>");
    h += row(QStringLiteral("Extraction ID"), report.extractionId);
    h += row(QStringLiteral("Extractor"), report.extractorId);
    h += row(QStringLiteral("Extractor version"), report.extractorVersion);
    h += row(QStringLiteral("Extraction result"), report.extractionStatus);
    h += QStringLiteral("</table>");

    h += QStringLiteral("<h2>Attack</h2><table>");
    h += row(QStringLiteral("Hash mode"), QStringLiteral("-m %1 (%2)").arg(report.hashMode).arg(report.hashModeName));
    h += row(QStringLiteral("Attack strategy"), QStringLiteral("-a %1 (%2)").arg(report.attackMode).arg(report.attackStrategy));
    h += row(QStringLiteral("Wordlists"), report.wordlists.join(QStringLiteral(", ")));
    if (!report.dictionaryId.isEmpty()) {
        const QString count = report.dictionaryCandidateCount >= 0
            ? QString::number(report.dictionaryCandidateCount)
            : QStringLiteral("(not recorded)");
        h += row(QStringLiteral("Dictionary"),
                 QStringLiteral("%1 (%2 candidates)").arg(report.dictionaryName, count));
        h += row(QStringLiteral("Dictionary SHA-256"), report.dictionarySha256);
    }
    h += row(QStringLiteral("Rules"), report.rules.join(QStringLiteral(", ")));
    h += row(QStringLiteral("Mask"), report.mask);
    h += QStringLiteral("<tr><th>Exact parameters</th><td><code>%1</code></td></tr>")
             .arg(esc(report.engineArgs.join(QLatin1Char(' '))));
    h += QStringLiteral("</table>");

    h += QStringLiteral("<h2>Recovery engine</h2><table>");
    h += row(QStringLiteral("Engine"),
             report.engineDisplayName.isEmpty() ? report.engineId : report.engineDisplayName);
    h += row(QStringLiteral("Version"), report.engineVersion);
    if (!report.enginePath.isEmpty())
        h += row(QStringLiteral("Executable"), report.enginePath);
    if (!report.engineExeSha256.isEmpty())
        h += row(QStringLiteral("Executable SHA-256"), report.engineExeSha256);
    h += row(QStringLiteral("Compute devices"), report.devices.join(QStringLiteral("; ")));
    h += QStringLiteral("</table>");

    h += QStringLiteral("<h2>Outcome</h2><table>");
    h += row(QStringLiteral("Started (UTC)"), report.startedUtc);
    h += row(QStringLiteral("Ended (UTC)"), report.endedUtc);
    h += row(QStringLiteral("Runtime"), runtime);
    h += row(QStringLiteral("Final status"), report.finalStatus);
    h += QStringLiteral("</table>");

    h += QStringLiteral("<h2>Recovered result</h2>");
    if (report.recovered) {
        // Label the value by its actual kind ("Password", "Key material", ...)
        // so key material is never described as a recovered password.
        QString valueLabel = report.recoveredKind.isEmpty()
            ? QStringLiteral("Value")
            : report.recoveredKind.left(1).toUpper() + report.recoveredKind.mid(1);
        h += QStringLiteral("<table class=\"rec\">");
        h += row(QStringLiteral("Result type"), report.recoveredKind);
        h += row(valueLabel, report.recoveredPlaintext);
        if (!report.recoveredEncoding.isEmpty())
            h += row(QStringLiteral("Encoding"), report.recoveredEncoding);
        h += row(QStringLiteral("Target"), report.recoveredHash);
        h += row(QStringLiteral("Recovered (UTC)"), report.recoveredUtc);
        h += QStringLiteral("</table>");
    } else {
        h += QStringLiteral("<p>Nothing recovered for this attempt.</p>");
    }

    h += QStringLiteral("</body></html>");
    return h;
}

} // namespace forensic

// SPDX-License-Identifier: GPL-3.0-or-later
#include "backend.h"

#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QJSEngine>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QProcess>
#include <QStandardPaths>

Backend::Backend(QObject *parent)
    : QObject(parent)
{
    m_cli = findTool(QStringLiteral("sam-jail"));
    m_runner = findTool(QStringLiteral("sam-jail-run"));
}

QString Backend::version() const
{
    return QCoreApplication::applicationVersion();
}

/// Lookup order: $SAM_CLI / $SAM_RUN, next to this binary,
/// the cargo target dir of a source checkout, then $PATH.
QString Backend::findTool(const QString &name) const
{
    const QByteArray envName = name == QLatin1String("sam-jail") ? "SAM_CLI" : "SAM_RUN";
    const QString fromEnv = qEnvironmentVariable(envName.constData());
    if (!fromEnv.isEmpty())
        return fromEnv;

    const QDir here(QCoreApplication::applicationDirPath());
    // Installed next to the GUI: use that.
    const QFileInfo beside(here.filePath(name));
    if (beside.isFile() && beside.isExecutable())
        return beside.canonicalFilePath();
    // Source checkout: release and debug builds may both exist; use the one
    // built most recently, so a stale build never shadows the current one.
    const QStringList candidates = {
        here.filePath(QStringLiteral("../../target/release/") + name),
        here.filePath(QStringLiteral("../../target/debug/") + name),
        here.filePath(QStringLiteral("../target/release/") + name),
        here.filePath(QStringLiteral("../target/debug/") + name),
    };
    QFileInfo best;
    for (const QString &c : candidates) {
        QFileInfo fi(c);
        if (fi.isFile() && fi.isExecutable() && (!best.exists() || fi.lastModified() > best.lastModified()))
            best = fi;
    }
    if (best.exists())
        return best.canonicalFilePath();
    const QString inPath = QStandardPaths::findExecutable(name);
    return inPath.isEmpty() ? name : inPath;
}

void Backend::call(const QStringList &args, const QJSValue &callback, const QString &input)
{
    auto *proc = new QProcess(this);
    proc->setProgram(m_cli);
    proc->setArguments(QStringList{QStringLiteral("--json")} + args);
    ++m_pending;
    Q_EMIT busyChanged();

    auto finish = [this, proc, callback](const QJsonObject &envelope) {
        if (callback.isCallable() && m_engine) {
            QJSValue cb = callback;
            cb.call({m_engine->toScriptValue(envelope.toVariantMap())});
        }
        proc->deleteLater();
        --m_pending;
        Q_EMIT busyChanged();
    };

    connect(proc, &QProcess::finished, this, [proc, finish](int, QProcess::ExitStatus) {
        const QByteArray out = proc->readAllStandardOutput();
        const QByteArray err = proc->readAllStandardError();
        // The envelope is the last JSON object line on stdout.
        QJsonObject envelope;
        const QList<QByteArray> lines = out.split('\n');
        for (auto it = lines.crbegin(); it != lines.crend(); ++it) {
            const QJsonDocument doc = QJsonDocument::fromJson(it->trimmed());
            if (doc.isObject() && doc.object().contains(QStringLiteral("ok"))) {
                envelope = doc.object();
                break;
            }
        }
        if (envelope.isEmpty()) {
            envelope.insert(QStringLiteral("ok"), false);
            const QString e = QString::fromUtf8(err).trimmed();
            envelope.insert(QStringLiteral("error"), e.isEmpty() ? QStringLiteral("No response from the sam-jail command line tool.") : e);
        }
        finish(envelope);
    });
    connect(proc, &QProcess::errorOccurred, this, [this, proc, finish](QProcess::ProcessError e) {
        if (e != QProcess::FailedToStart)
            return;
        QJsonObject envelope;
        envelope.insert(QStringLiteral("ok"), false);
        envelope.insert(QStringLiteral("error"), QStringLiteral("Could not start '%1'. Is SAM installed correctly?").arg(m_cli));
        finish(envelope);
    });

    proc->start();
    if (!input.isEmpty())
        proc->write(input.toUtf8());
    proc->closeWriteChannel();
}

bool Backend::launch(const QString &appId, const QStringList &files)
{
    // No parent: a QProcess owned by Backend would be killed when SAM's
    // window closes, taking the sandboxed app with it (bwrap
    // --die-with-parent). Apps keep running after SAM exits; while SAM
    // runs, `finished` still reports failures.
    auto *proc = new QProcess();
    proc->setProgram(m_runner);
    proc->setArguments(QStringList{QStringLiteral("--app-id"), appId} + files);
    proc->setProcessChannelMode(QProcess::ForwardedChannels);
    connect(proc, &QProcess::finished, this, [this, proc, appId](int code, QProcess::ExitStatus) {
        Q_EMIT appFinished(appId, code);
        proc->deleteLater();
    });
    proc->start();
    return proc->waitForStarted(3000);
}

void Backend::copyToClipboard(const QString &text)
{
    QGuiApplication::clipboard()->setText(text);
}

QString Backend::urlToPath(const QUrl &url) const
{
    return url.isLocalFile() ? url.toLocalFile() : url.toString();
}

QUrl Backend::pathToUrl(const QString &path) const
{
    return QUrl::fromLocalFile(path);
}

bool Backend::fileExists(const QString &path) const
{
    return !path.isEmpty() && QFileInfo::exists(path);
}

QString Backend::homeDir() const
{
    return QDir::homePath();
}

QString Backend::formatTime(qint64 unixSeconds) const
{
    if (unixSeconds <= 0)
        return tr("Never");
    const QDateTime t = QDateTime::fromSecsSinceEpoch(unixSeconds);
    return QLocale().toString(t, QLocale::ShortFormat);
}

QString Backend::humanSize(qint64 bytes) const
{
    return QLocale().formattedDataSize(bytes);
}

void Backend::openFolder(const QString &path)
{
    QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(path).isDir() ? path : QFileInfo(path).absolutePath()));
}

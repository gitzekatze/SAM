// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QJSValue>
#include <QObject>
#include <QStringList>
#include <QUrl>

class QJSEngine;

/// Bridge between QML and the Rust core. Every call runs
/// `sam-jail --json <args>` asynchronously and hands the parsed JSON
/// envelope (`{ok, data, error}`) to a JavaScript callback.
class Backend : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QString cliPath READ cliPath CONSTANT)
    Q_PROPERTY(QString runnerPath READ runnerPath CONSTANT)
    Q_PROPERTY(QString startupPage READ startupPage CONSTANT)
    Q_PROPERTY(QString startupApp READ startupApp CONSTANT)
    Q_PROPERTY(QString version READ version CONSTANT)
    Q_PROPERTY(QStringList startupFiles READ startupFiles CONSTANT)

public:
    explicit Backend(QObject *parent = nullptr);

    void setEngine(QJSEngine *engine) { m_engine = engine; }
    void setStartup(const QString &page, const QString &app)
    {
        m_startupPage = page;
        m_startupApp = app;
    }

    void setStartupFiles(const QStringList &files) { m_startupFiles = files; }
    QStringList startupFiles() const { return m_startupFiles; }

    bool busy() const { return m_pending > 0; }
    QString cliPath() const { return m_cli; }
    QString runnerPath() const { return m_runner; }
    QString startupPage() const { return m_startupPage; }
    QString startupApp() const { return m_startupApp; }
    QString version() const;

    /// Run `sam-jail --json <args>`; `input` is written to stdin when non-empty.
    Q_INVOKABLE void call(const QStringList &args, const QJSValue &callback, const QString &input = QString());
    /// Start an app detached through sam-jail-run (like the desktop launcher).
    Q_INVOKABLE bool launch(const QString &appId, const QStringList &files = {});
    Q_INVOKABLE void copyToClipboard(const QString &text);
    Q_INVOKABLE QString urlToPath(const QUrl &url) const;
    Q_INVOKABLE QUrl pathToUrl(const QString &path) const;
    Q_INVOKABLE bool fileExists(const QString &path) const;
    Q_INVOKABLE QString homeDir() const;
    Q_INVOKABLE QString formatTime(qint64 unixSeconds) const;
    Q_INVOKABLE QString humanSize(qint64 bytes) const;
    Q_INVOKABLE void openFolder(const QString &path);

Q_SIGNALS:
    void busyChanged();
    /// Emitted when an app started from the GUI exits.
    void appFinished(const QString &appId, int exitCode);

private:
    QString findTool(const QString &name) const;

    QJSEngine *m_engine = nullptr;
    QString m_cli;
    QString m_runner;
    QString m_startupPage;
    QString m_startupApp;
    QStringList m_startupFiles;
    int m_pending = 0;
};

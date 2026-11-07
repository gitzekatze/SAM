// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QObject>
#include <QString>

/// Applies one of SAM's four KDE color schemes (Breeze Light, Breeze
/// Dark, Breeze High Contrast, CachyOS Neon) to the whole application,
/// the same way KColorSchemeManager does.
class ThemeManager : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString current READ current NOTIFY currentChanged)
    Q_PROPERTY(QStringList themes READ themes CONSTANT)

public:
    explicit ThemeManager(QObject *parent = nullptr);

    QString current() const { return m_current; }
    QStringList themes() const;

    Q_INVOKABLE bool apply(const QString &themeId);
    Q_INVOKABLE QString label(const QString &themeId) const;

Q_SIGNALS:
    void currentChanged();

private:
    QString schemeFile(const QString &themeId) const;
    QString m_current;
};

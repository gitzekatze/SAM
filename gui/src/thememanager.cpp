// SPDX-License-Identifier: GPL-3.0-or-later
#include "thememanager.h"

#include <KColorScheme>
#include <KSharedConfig>

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QStandardPaths>

ThemeManager::ThemeManager(QObject *parent)
    : QObject(parent)
{
}

QStringList ThemeManager::themes() const
{
    return {QStringLiteral("breeze-light"), QStringLiteral("breeze-dark"), QStringLiteral("breeze-high-contrast"), QStringLiteral("cachyos-neon")};
}

QString ThemeManager::label(const QString &themeId) const
{
    if (themeId == QLatin1String("breeze-light"))
        return tr("Breeze Light");
    if (themeId == QLatin1String("breeze-dark"))
        return tr("Breeze Dark");
    if (themeId == QLatin1String("breeze-high-contrast"))
        return tr("Breeze High Contrast");
    if (themeId == QLatin1String("cachyos-neon"))
        return tr("CachyOS Neon");
    return themeId;
}

/// KConfig cannot read from Qt resources, so the bundled scheme is copied to
/// the cache directory once and loaded from there.
QString ThemeManager::schemeFile(const QString &themeId) const
{
    const QString res = QStringLiteral(":/qt/qml/Appseal/themes/%1.colors").arg(themeId);
    if (!QFile::exists(res))
        return {};
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::GenericCacheLocation) + QStringLiteral("/appseal/themes");
    QDir().mkpath(dir);
    const QString out = dir + QLatin1Char('/') + themeId + QStringLiteral(".colors");
    QFile::remove(out);
    if (!QFile::copy(res, out))
        return {};
    QFile::setPermissions(out, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    return out;
}

bool ThemeManager::apply(const QString &themeId)
{
    const QString file = schemeFile(themeId);
    if (file.isEmpty())
        return false;
    auto config = KSharedConfig::openConfig(file, KConfig::SimpleConfig);
    // Kirigami's desktop theme reads this property, like with KColorSchemeManager.
    qApp->setProperty("KDE_COLOR_SCHEME_PATH", file);
    QApplication::setPalette(KColorScheme::createApplicationPalette(config));
    m_current = themeId;
    Q_EMIT currentChanged();
    return true;
}

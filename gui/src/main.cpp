// SPDX-License-Identifier: GPL-3.0-or-later
//
// SAM GUI entry point.
//
//   sam-jail-gui [--page dashboard|app|presets|settings|diagnostics] [--app <id>]
//   sam-jail-gui --screenshot out.png [--page ...] [--app <id>] [--size 1200x800]
//
// --screenshot renders the window (works with QT_QPA_PLATFORM=offscreen),
// saves it and exits; used for documentation and UI checks.

#include <QApplication>
#include <QCommandLineParser>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QTimer>

#include "backend.h"
#include "thememanager.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("sam"));
    QApplication::setApplicationDisplayName(QStringLiteral("SAM"));
    QApplication::setOrganizationDomain(QStringLiteral("gitzekatze.github.io"));
    QApplication::setApplicationVersion(QStringLiteral("0.1.0"));
    QApplication::setDesktopFileName(QStringLiteral("io.github.gitzekatze.SAM"));
    QApplication::setWindowIcon(QIcon(QStringLiteral(":/qt/qml/SAM/icons/sam.svg")));

    if (qEnvironmentVariableIsEmpty("QT_QUICK_CONTROLS_STYLE"))
        QQuickStyle::setStyle(QStringLiteral("org.kde.desktop"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Flatseal-style permission manager for AppImages"));
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption pageOpt(QStringLiteral("page"), QStringLiteral("Page to open."), QStringLiteral("page"));
    QCommandLineOption appOpt(QStringLiteral("app"), QStringLiteral("App id to open."), QStringLiteral("id"));
    QCommandLineOption shotOpt(QStringLiteral("screenshot"), QStringLiteral("Save a screenshot and exit."), QStringLiteral("file"));
    QCommandLineOption sizeOpt(QStringLiteral("size"), QStringLiteral("Window size for screenshots."), QStringLiteral("WxH"), QStringLiteral("1180x780"));
    QCommandLineOption delayOpt(QStringLiteral("delay"), QStringLiteral("Screenshot delay in ms."), QStringLiteral("ms"), QStringLiteral("2500"));
    parser.addOptions({pageOpt, appOpt, shotOpt, sizeOpt, delayOpt});
    parser.addPositionalArgument(QStringLiteral("files"), QStringLiteral("AppImages to add."), QStringLiteral("[files...]"));
    parser.process(app);

    Backend backend;
    backend.setStartup(parser.value(pageOpt), parser.value(appOpt));
    backend.setStartupFiles(parser.positionalArguments());
    ThemeManager themes;

    QQmlApplicationEngine engine;
    backend.setEngine(&engine);
    qmlRegisterSingletonInstance("SAM.Native", 1, 0, "Backend", &backend);
    qmlRegisterSingletonInstance("SAM.Native", 1, 0, "Themes", &themes);
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app, [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
    engine.loadFromModule("SAM", "Main");
    if (engine.rootObjects().isEmpty())
        return 1;

    if (parser.isSet(shotOpt)) {
        auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().constFirst());
        const QStringList wh = parser.value(sizeOpt).split(QLatin1Char('x'));
        if (window && wh.size() == 2)
            window->resize(wh[0].toInt(), wh[1].toInt());
        const QString file = parser.value(shotOpt);
        QTimer::singleShot(parser.value(delayOpt).toInt(), &app, [window, file] {
            if (window)
                window->grabWindow().save(file);
            QCoreApplication::quit();
        });
    }
    return app.exec();
}

cmake_minimum_required(VERSION 3.21)
project(appseal-gui VERSION 0.1.0 LANGUAGES CXX)

# Appseal GUI: a thin Qt6/QML/Kirigami shell over the Rust core.
# The shell talks to the core through `appseal --json ...` (see src/backend.cpp).

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Widgets Qml Quick QuickControls2)
find_package(KF6Config REQUIRED)
find_package(KF6ColorScheme REQUIRED)
find_package(KF6Kirigami REQUIRED)

qt_standard_project_setup(REQUIRES 6.5)
if(QT_KNOWN_POLICY_QTP0004)
    qt_policy(SET QTP0004 NEW)
endif()

qt_add_executable(appseal-gui
    src/main.cpp
    src/backend.cpp src/backend.h
    src/thememanager.cpp src/thememanager.h
)

qt_add_qml_module(appseal-gui
    URI Appseal
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/DashboardPage.qml
        qml/AppPage.qml
        qml/PermissionsEditor.qml
        qml/PermSwitch.qml
        qml/PermChoice.qml
        qml/PathListEditor.qml
        qml/PresetsPage.qml
        qml/PresetEditorPage.qml
        qml/SettingsPage.qml
        qml/DiagnosticsPage.qml
        qml/OnboardingDialog.qml
        qml/StatusBadge.qml
        qml/RiskChip.qml
        qml/WarningList.qml
        qml/ScanDialog.qml
        qml/PresetPickerDialog.qml
        qml/TextInputDialog.qml
        qml/ConfirmDialog.qml
        qml/AppIcon.qml
        qml/Util.js
    RESOURCES
        themes/breeze-light.colors
        themes/breeze-dark.colors
        themes/breeze-high-contrast.colors
        themes/cachyos-neon.colors
        icons/appseal.svg
)

target_link_libraries(appseal-gui PRIVATE
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Qml Qt6::Quick Qt6::QuickControls2
    KF6::ConfigCore KF6::ColorScheme
)

install(TARGETS appseal-gui RUNTIME DESTINATION bin)

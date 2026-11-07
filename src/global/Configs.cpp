#include "include/global/Configs.hpp"

#include <algorithm>
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeySequence>
#include <QNetworkAccessManager>
#include <QStandardPaths>
#include <utility>
#include <include/api/RPC.h>

#include "include/database/GroupsRepo.h"
#include "include/database/ProfilesRepo.h"
#include "include/database/RoutesRepo.h"
#include "include/configs/OmnitServiceRouting.hpp"


#ifdef Q_OS_WIN
#include "include/sys/windows/guihelper.h"
#else
#ifdef Q_OS_LINUX
#include <include/sys/linux/LinuxCap.h>
#endif
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

    // System Utils
namespace Configs {
    void initDB(const std::string& dbPath) {
        dataManager = new DatabaseManager(dbPath);

        if (dataManager->groupsRepo->GetAllGroupIds().empty()) {
            auto defaultGroup = GroupsRepo::NewGroup();
            defaultGroup->name = QObject::tr("Default");
            if (dataManager->groupsRepo->AddGroup(defaultGroup)) {
                dataManager->settingsRepo->current_group = defaultGroup->id;
            }
        }
        if (dataManager->profilesRepo->GetAllProfileIds().empty()) {
            auto happBridge = ProfilesRepo::NewProfile("socks");
            happBridge->outbound->name = "HAPP Bridge";
            happBridge->Socks()->server = "127.0.0.1";
            happBridge->Socks()->server_port = 10808;
            happBridge->Socks()->version = 5;
            dataManager->profilesRepo->AddProfile(happBridge);
        }
        const bool initializedRoutes = dataManager->routesRepo->GetAllRouteProfileIds().empty();
        if (initializedRoutes) {
            auto defaultRoute = RouteProfile::GetOmnitWhitelist();
            if (dataManager->routesRepo->AddRouteProfile(defaultRoute)) {
                auto* settings = dataManager->settingsRepo.get();
                settings->current_route_id = defaultRoute->id;
                settings->active_routing = defaultRoute->name;
                settings->enable_dns_routing = true;
                settings->dns_final_out = "direct";
                settings->remote_dns = "https://1.1.1.1/dns-query";
                settings->direct_dns = "localhost";
                settings->disable_private_range_bypass = false;
                settings->Save();
            }
        } else {
            // Keep existing OMNIT databases on the current managed-rule shape.
            // The first switch migration infers every choice from the legacy
            // aggregate rule, so no user's working route is silently reset.
            for (const auto& route : dataManager->routesRepo->GetAllRouteProfiles()) {
                if (!route || route->name != "OMNIT Whitelist") continue;
                const auto stock = RouteProfile::GetOmnitWhitelist();
                bool changed = false;
                const auto findRule = [](const auto& rules, const QString& name) {
                    return std::find_if(rules.cbegin(), rules.cend(), [&](const auto& rule) {
                        return rule && rule->name == name;
                    });
                };
                const auto stockOmnitBypass = findRule(stock->Rules, "OMNIT core bypass");
                const auto stockHappBypass = findRule(stock->Rules, "HAPP core bypass");
                if (findRule(route->Rules, "HAPP core bypass") == route->Rules.cend() &&
                    stockHappBypass != stock->Rules.cend()) {
                    route->Rules.prepend(*stockHappBypass);
                    changed = true;
                }
                if (findRule(route->Rules, "OMNIT core bypass") == route->Rules.cend() &&
                    stockOmnitBypass != stock->Rules.cend()) {
                    route->Rules.prepend(*stockOmnitBypass);
                    changed = true;
                }

                const bool hasManagedSwitches = std::any_of(
                    route->Rules.cbegin(), route->Rules.cend(), [](const auto& rule) {
                        return rule && rule->name.startsWith("OMNIT switch:");
                    });
                const bool hasCompleteManagedCatalog = hasManagedSwitches && std::all_of(
                    OmnitServiceCatalog().cbegin(), OmnitServiceCatalog().cend(),
                    [&](const auto& service) {
                        const auto prefix = QStringLiteral("OMNIT switch:") + service.id + QLatin1Char(':');
                        return std::any_of(route->Rules.cbegin(), route->Rules.cend(),
                                           [&](const auto& rule) {
                                               return rule && rule->name.startsWith(prefix);
                                           });
                    });
                if (!hasCompleteManagedCatalog) {
                    // Existing owner choices survive through Read..., while a
                    // newly shipped service receives only its reviewed default.
                    // This makes catalog additions available without resetting
                    // the entire whitelist in the UI.
                    const auto choices = ReadOmnitServiceChoices(route);
                    ApplyOmnitServiceChoices(route, choices);
                    changed = true;
                }

                auto infrastructure = findRule(route->Rules, "OMNIT infrastructure");
                if (infrastructure == route->Rules.cend()) {
                    const auto stockInfrastructure = findRule(stock->Rules, "OMNIT infrastructure");
                    if (stockInfrastructure != stock->Rules.cend()) {
                        route->Rules.append(*stockInfrastructure);
                        infrastructure = std::prev(route->Rules.end());
                        changed = true;
                    }
                }
                if (infrastructure != route->Rules.cend()) {
                    for (const auto& domain : {QStringLiteral("sourceforge.net"),
                                               QStringLiteral("therobottate.today")}) {
                        if (!(*infrastructure)->domain_suffix.contains(domain)) {
                            (*infrastructure)->domain_suffix.append(domain);
                            changed = true;
                        }
                    }
                }
                if (changed) dataManager->routesRepo->Save(route);
            }
        }

        // A green TUN switch only means that packets reach Throne. The route
        // profile decides whether they leave via the selected VPN or directly.
        // Keep an explicit managed full-tunnel profile so the desktop shell can
        // truthfully offer an all-applications mode instead of overloading the
        // split-tunnel whitelist.
        std::shared_ptr<RouteProfile> fullTunnel;
        for (const auto& route : dataManager->routesRepo->GetAllRouteProfiles()) {
            if (route && route->name == "OMNIT Full Tunnel") {
                fullTunnel = route;
                break;
            }
        }
        if (!fullTunnel) {
            fullTunnel = RouteProfile::GetOmnitFullTunnel();
            if (!dataManager->routesRepo->AddRouteProfile(fullTunnel)) fullTunnel.reset();
        }

        // Full tunnel is the safe default for a fresh OMNIT install. Existing
        // installations retain their current route until the owner switches it.
        if (initializedRoutes && fullTunnel) {
            auto* settings = dataManager->settingsRepo.get();
            settings->current_route_id = fullTunnel->id;
            settings->active_routing = fullTunnel->name;
            settings->enable_dns_routing = true;
            settings->dns_final_out = "remote";
            settings->Save();
        }
    }

    QString FindCoreRealPath() {
        auto fn = QApplication::applicationDirPath() + "/ThroneCore";
#ifdef Q_OS_WIN
        fn += ".exe";
#endif
        auto fi = QFileInfo(fn);
        QString path;
        if (fi.isSymLink()) path =  fi.symLinkTarget();
        path = fn;
#ifdef Q_OS_WIN
        path.replace("/", "\\");
#endif
        return path;
    }

    short isAdminCache = -1;

    bool isSetuidSet(const std::string& path) {
#ifdef Q_OS_MACOS
        struct stat fileInfo;

        if (stat(path.c_str(), &fileInfo) != 0) {
            return false;
        }

        if (fileInfo.st_mode & S_ISUID) {
            return true;
        } else {
            return false;
        }
#else
        return false;
#endif
    }

    // IsAdmin 主要判断：有无权限启动 Tun
    bool IsAdmin(bool forceRenew) {
        if (isAdminCache >= 0 && !forceRenew) return isAdminCache;

        bool admin = false;
#ifdef Q_OS_WIN
        admin = Windows_IsInAdmin();
        Configs::dataManager->settingsRepo->windows_set_admin = admin;
#else
        // Unknown until the core answers; caching that would pin "not elevated" for the session.
        if (API::defaultClient == nullptr) return false;
        bool ok;
        const auto isPrivileged = API::defaultClient->IsPrivileged(&ok);
        if (!ok) return false;
        admin = isPrivileged;
#endif
        isAdminCache = admin;
        return admin;
    }

    QString GetBasePath() {
        if (Configs::dataManager->settingsRepo->flag_use_appdata) return QStandardPaths::writableLocation(
              QStandardPaths::AppConfigLocation);
        return qApp->applicationDirPath();
    }
} // namespace Configs

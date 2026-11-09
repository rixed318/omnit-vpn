#include "include/ui/mainwindow.h"

#include <algorithm>

#include <QBuffer>
#include <QFileInfo>
#include <QImageReader>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonParseError>
#include <QMessageBox>
#include <QScopedValueRollback>
#include <QStringConverter>
#include <QUrl>

#include "3rdparty/QrDecoder.h"
#include "include/configs/sub/GroupUpdater.hpp"
#include "include/configs/sub/RouteUpdater.hpp"
#include "include/configs/OmnitServiceRouting.hpp"
#include "include/database/GroupsRepo.h"
#include "include/database/ProfilesRepo.h"
#include "include/database/RoutesRepo.h"
#include "include/global/PeriodicRunner.hpp"
#include "include/sys/AutoRun.hpp"
#include "include/ui/mainWindow/MainWindowInternal.h"
#include "include/ui/utils/ProfilesTableModel.h"

namespace {

constexpr qint64 kMaxImportFileSize = 50 * 1024 * 1024;

// Content-sniffs text vs binary: the name promises nothing (.json/.conf/.txt/none).
// A BOM also pins the encoding and is dropped - Qt's json parser rejects it.
bool decodeImportedText(const QByteArray &bytes, QString &out) {
    if (const auto encoding = QStringConverter::encodingForData(bytes)) {
        QStringDecoder decoder(*encoding);
        out = decoder(bytes);
        return !decoder.hasError();
    }

    // No BOM: reject NUL bytes or a heavy control-character share, then decode leniently
    // so a legacy 8-bit config still parses with only its names garbled.
    const qsizetype sample = std::min<qsizetype>(bytes.size(), 8192);
    qsizetype control = 0;
    for (qsizetype i = 0; i < sample; i++) {
        const auto c = static_cast<unsigned char>(bytes[i]);
        if (c == 0) return false;
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f' && c != 0x1B) control++;
    }
    if (control * 20 > sample) return false;

    out = QString::fromUtf8(bytes);
    return true;
}

QString omnitRouteMode(const std::shared_ptr<Configs::RouteProfile> &route) {
    if (!route) return QStringLiteral("unknown");
    if (route->name == QStringLiteral("OMNIT Full Tunnel")) return QStringLiteral("full");
    if (route->name == QStringLiteral("OMNIT Whitelist")) return QStringLiteral("split");
    if (route->name == QStringLiteral("OMNIT Smart")) return QStringLiteral("smart");
    return QStringLiteral("custom");
}

bool supportsOmnitServiceChoices(const std::shared_ptr<Configs::RouteProfile> &route) {
    return route && !route->isRaw && omnitRouteMode(route) == QStringLiteral("split");
}

} // namespace

QByteArray MainWindow::handleOmnitControlRequest(const QByteArray &request) {
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(request, &parseError);
    QJsonObject response;
    response["apiVersion"] = 1;
    response["app"] = QStringLiteral("OMNIT VPN");
    response["guiRunning"] = true;

    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        response["ok"] = false;
        response["error"] = QStringLiteral("invalid_json");
        return QJsonDocument(response).toJson(QJsonDocument::Compact);
    }

    const QJsonObject input = document.object();
    if (input.value("apiVersion").toInt() != 1) {
        response["ok"] = false;
        response["error"] = QStringLiteral("unsupported_api_version");
        return QJsonDocument(response).toJson(QJsonDocument::Compact);
    }

    // Socket clients have short timeouts and may retry unattended. Report the
    // missing privilege instead of opening a modal dialog inside their request.
    QScopedValueRollback<bool> suppressPrompts(m_suppressConnectionPrompts, true);
    QScopedValueRollback<bool> privilegeRequired(m_privilegeRequired, false);
    QScopedValueRollback<QString> connectionError(m_controlConnectionError, QString());
    const auto &settings = Configs::dataManager->settingsRepo;
    const QString action = input.value("action").toString(QStringLiteral("status"));
    bool accepted = true;
    if (action == "status") {
        // Snapshot only.
    } else if (action == "connect") {
        if (running == nullptr && !m_profileConnecting) profile_start();
    } else if (action == "disconnect") {
        if (running != nullptr && !m_profileDisconnecting) profile_stop(false, false, true);
    } else if (action == "toggle") {
        if (running != nullptr) profile_stop(false, false, true);
        else if (!m_profileConnecting) profile_start();
    } else if (action == "set-tun") {
        if (!input.value("enabled").isBool()) {
            accepted = false;
            response["error"] = QStringLiteral("enabled_must_be_boolean");
        } else {
            set_spmode_vpn(input.value("enabled").toBool());
        }
    } else if (action == "select-profile") {
        if (!input.value("profileId").isDouble()) {
            accepted = false;
            response["error"] = QStringLiteral("profile_id_must_be_integer");
        } else {
            const int profileId = input.value("profileId").toInt(-1);
            const auto selected = Configs::dataManager->profilesRepo->GetProfile(profileId);
            const auto group = selected
                                   ? Configs::dataManager->groupsRepo->GetGroup(selected->gid)
                                   : nullptr;
            if (!selected || !group || group->archive) {
                accepted = false;
                response["error"] = QStringLiteral("profile_not_found");
            } else if (!m_profileConnecting && !m_profileDisconnecting) {
                show_group(group->id);
                profile_start(profileId);
            }
        }
    } else if (action == "set-route") {
        if (!input.value("routeId").isDouble()) {
            accepted = false;
            response["error"] = QStringLiteral("route_id_must_be_integer");
        } else {
            const int routeId = input.value("routeId").toInt(-1);
            const auto selectedRoute = Configs::dataManager->routesRepo->GetRouteProfile(routeId);
            if (!selectedRoute) {
                accepted = false;
                response["error"] = QStringLiteral("route_not_found");
            } else {
                settings->current_route_id = selectedRoute->id;
                settings->active_routing = selectedRoute->name;
                const QString routeMode = omnitRouteMode(selectedRoute);
                if (routeMode == QStringLiteral("full")) {
                    settings->enable_dns_routing = true;
                    settings->dns_final_out = QStringLiteral("remote");
                } else if (routeMode == QStringLiteral("split")) {
                    settings->enable_dns_routing = true;
                    settings->dns_final_out = QStringLiteral("direct");
                }
                settings->Save();
                if (settings->started_id >= 0 && !m_profileConnecting && !m_profileDisconnecting)
                    profile_start(settings->started_id);
            }
        }
    } else if (action == "set-services") {
        const auto selectedRoute = Configs::dataManager->routesRepo->GetRouteProfile(
            settings->current_route_id);
        if (!input.value("choices").isObject()) {
            accepted = false;
            response["error"] = QStringLiteral("choices_must_be_object");
        } else if (!supportsOmnitServiceChoices(selectedRoute)) {
            accepted = false;
            response["error"] = QStringLiteral("route_does_not_support_service_choices");
        } else {
            auto choices = Configs::ReadOmnitServiceChoices(selectedRoute);
            const auto supplied = input.value("choices").toObject();
            for (const auto &service : Configs::OmnitServiceCatalog()) {
                if (supplied.contains(service.id) && supplied.value(service.id).isBool())
                    choices.insert(service.id, supplied.value(service.id).toBool());
            }
            Configs::ApplyOmnitServiceChoices(selectedRoute, choices);
            if (!Configs::dataManager->routesRepo->Save(selectedRoute)) {
                accepted = false;
                response["error"] = QStringLiteral("could_not_save_service_choices");
            } else {
                settings->active_routing = selectedRoute->name;
                settings->Save();
                if (settings->started_id >= 0 && !m_profileConnecting && !m_profileDisconnecting)
                    profile_start(settings->started_id);
            }
        }
    } else if (action == "add-subscription") {
        const QString subscriptionUrl = input.value("url").toString().trimmed();
        const QUrl parsed(subscriptionUrl);
        if (subscriptionUrl.size() > 8192 || !parsed.isValid() ||
            parsed.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) != 0 ||
            parsed.host().isEmpty()) {
            accepted = false;
            response["error"] = QStringLiteral("subscription_url_must_be_https");
        } else {
            QString groupName = input.value("name").toString().trimmed();
            if (groupName.isEmpty()) groupName = parsed.host();
            if (groupName.size() > 96) groupName = groupName.left(96);

            std::shared_ptr<Configs::Group> target;
            for (const int groupId : Configs::dataManager->groupsRepo->GetAllGroupIds()) {
                const auto candidate = Configs::dataManager->groupsRepo->GetGroup(groupId);
                if (candidate && candidate->url == subscriptionUrl) {
                    target = candidate;
                    break;
                }
            }
            if (!target) {
                target = Configs::GroupsRepo::NewGroup();
                target->name = groupName;
                target->url = subscriptionUrl;
                target->skip_auto_update = false;
                if (!Configs::dataManager->groupsRepo->AddGroup(target)) {
                    accepted = false;
                    response["error"] = QStringLiteral("could_not_create_subscription_group");
                } else {
                    refresh_groups();
                }
            }
            if (accepted && target) {
                QJsonObject subscription;
                subscription["groupId"] = target->id;
                subscription["name"] = target->name;
                subscription["refreshStarted"] = true;
                response["subscription"] = subscription;
                Subscription::groupUpdater->AsyncUpdate(subscriptionUrl, target->id);
            }
        }
    } else if (action == "restart") {
        QTimer::singleShot(120, this, [this] {
            exit_reason = ExitReason::Restart;
            on_menu_exit_triggered();
        });
    } else if (action == "catalog") {
        // Catalog payload is appended below after the common status snapshot.
    } else if (action == "show") {
        ActivateWindow(this);
    } else if (action == "services") {
        ActivateWindow(this);
        on_menu_omnit_services_triggered();
    } else if (action == "routing") {
        ActivateWindow(this);
        on_menu_routing_settings_triggered();
    } else if (action == "refresh-subscription") {
        on_menu_update_subscription_triggered();
    } else {
        accepted = false;
        response["error"] = QStringLiteral("unknown_action");
    }

    if (Configs::IsAdmin(true)) {
        m_privilegeRequired = false;
    }

    if (m_privilegeRequired) {
        accepted = false;
        response["error"] = QStringLiteral("core_privileges_required");
    } else if (!m_controlConnectionError.isEmpty()) {
        accepted = false;
        response["error"] = m_controlConnectionError;
    } else if (action == "status" || action == "catalog") {
        response["error"] = m_lastConnectionError;
    }

    QString state = QStringLiteral("idle");
    if (m_profileConnecting) state = QStringLiteral("connecting");
    else if (m_profileDisconnecting) state = QStringLiteral("disconnecting");
    else if (running != nullptr) state = QStringLiteral("connected");

    response["ok"] = accepted;
    response["accepted"] = accepted;
    response["state"] = state;
    response["connected"] = running != nullptr;
    response["coreRunning"] = settings->core_running;
    response["elevated"] = Configs::IsAdmin();
    response["tunEnabled"] = settings->spmode_vpn;
    response["systemProxyEnabled"] = settings->spmode_system_proxy;
    response["updatedAt"] = QDateTime::currentMSecsSinceEpoch();

    QJsonObject profile;
    if (running != nullptr) {
        profile["id"] = running->id;
        profile["name"] = running->name;
        profile["type"] = running->type;
        profile["location"] = running->runningCountryInfo;
        if (const auto group = Configs::dataManager->groupsRepo->GetGroup(running->gid)) {
            profile["group"] = group->name;
        }
    } else {
        const int availableId = get_profile_to_start();
        if (availableId >= 0) {
            if (const auto available = Configs::dataManager->profilesRepo->GetProfile(availableId)) {
                profile["id"] = available->id;
                profile["name"] = available->name;
                profile["type"] = available->type;
                if (const auto group = Configs::dataManager->groupsRepo->GetGroup(available->gid)) {
                    profile["group"] = group->name;
                }
            }
        }
    }
    response["profile"] = profile;

    QJsonObject route;
    route["id"] = settings->current_route_id;
    if (const auto activeRoute = Configs::dataManager->routesRepo->GetRouteProfile(settings->current_route_id)) {
        route["name"] = activeRoute->name;
        route["mode"] = omnitRouteMode(activeRoute);
    }
    response["route"] = route;

    QJsonObject mixed;
    mixed["enabled"] = !settings->disable_mixed_inbound;
    mixed["address"] = settings->inbound_address;
    mixed["port"] = settings->inbound_socks_port;
    response["mixed"] = mixed;

    QJsonObject rates;
    rates["proxyDownload"] = m_proxyDownloadRate;
    rates["proxyUpload"] = m_proxyUploadRate;
    rates["directDownload"] = m_directDownloadRate;
    rates["directUpload"] = m_directUploadRate;
    response["rates"] = rates;

    QJsonArray capabilities;
    for (const auto &capability : {
             QStringLiteral("status"), QStringLiteral("connect"),
             QStringLiteral("disconnect"), QStringLiteral("set-tun"),
             QStringLiteral("select-profile"), QStringLiteral("set-route"),
             QStringLiteral("catalog"), QStringLiteral("set-services"),
             QStringLiteral("add-subscription"), QStringLiteral("refresh-subscription"),
             QStringLiteral("restart"), QStringLiteral("show")}) {
        capabilities.append(capability);
    }
    response["capabilities"] = capabilities;

    if (action == "catalog") {
        QJsonArray groups;
        for (const int groupId : Configs::dataManager->groupsRepo->GetGroupsTabOrder()) {
            const auto groupEntity = Configs::dataManager->groupsRepo->GetGroup(groupId);
            if (!groupEntity || groupEntity->archive) continue;
            QJsonObject groupObject;
            groupObject["id"] = groupEntity->id;
            groupObject["name"] = groupEntity->name;
            QJsonArray profiles;
            for (const auto &profileEntity :
                 Configs::dataManager->profilesRepo->GetProfileBatch(groupEntity->Profiles())) {
                if (!profileEntity) continue;
                QJsonObject item;
                item["id"] = profileEntity->id;
                item["name"] = profileEntity->name;
                item["type"] = profileEntity->type;
                item["latencyMs"] = profileEntity->latency;
                item["country"] = profileEntity->test_country;
                item["selected"] = profile.value("id").toInt(-1) == profileEntity->id;
                profiles.append(item);
            }
            groupObject["profiles"] = profiles;
            groups.append(groupObject);
        }
        response["groups"] = groups;

        QJsonArray routes;
        for (const auto &routeEntity : Configs::dataManager->routesRepo->GetAllRouteProfiles()) {
            if (!routeEntity) continue;
            QJsonObject item;
            item["id"] = routeEntity->id;
            item["name"] = routeEntity->name;
            item["mode"] = omnitRouteMode(routeEntity);
            item["selected"] = routeEntity->id == settings->current_route_id;
            item["serviceChoicesSupported"] = supportsOmnitServiceChoices(routeEntity);
            routes.append(item);
        }
        response["routes"] = routes;

        const auto selectedRoute = Configs::dataManager->routesRepo->GetRouteProfile(
            settings->current_route_id);
        const auto choices = Configs::ReadOmnitServiceChoices(selectedRoute);
        QJsonArray services;
        for (const auto &service : Configs::OmnitServiceCatalog()) {
            QJsonObject item;
            item["id"] = service.id;
            item["title"] = service.title;
            item["description"] = service.description;
            item["category"] = service.category;
            item["useProxy"] = choices.value(service.id, service.defaultProxy);
            item["recommendedProxy"] = service.defaultProxy;
            item["automatic"] = service.broadCategory;
            item["confidence"] = service.confidence;
            item["securitySensitive"] = service.securitySensitive;
            services.append(item);
        }
        response["services"] = services;
        response["serviceChoicesSupported"] = supportsOmnitServiceChoices(selectedRoute);
    }

    return QJsonDocument(response).toJson(QJsonDocument::Compact);
}

void MainWindow::importFromFiles(const QStringList &paths)
{
    QStringList payloads;
    QStringList problems;

    for (const QString &path : paths) {
        const auto name = QFileInfo(path).fileName();
        auto file = QFile(path);
        if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
            problems << tr("%1: cannot be opened").arg(name);
            continue;
        }
        if (file.size() > kMaxImportFileSize) {
            file.close();
            problems << tr("%1: larger than 50 MB, skipped").arg(name);
            continue;
        }
        const auto bytes = file.readAll();
        file.close();

        // Decide the type from the bytes rather than the suffix, so a QR code
        // screenshot saved without one still reaches the decoder.
        QBuffer buffer;
        buffer.setData(bytes);
        buffer.open(QIODevice::ReadOnly);
        QImageReader reader(&buffer);
        reader.setDecideFormatFromContent(true);
        if (reader.canRead()) {
            const auto image = reader.read();
            const QVector<QString> texts = image.isNull()
                                               ? QVector<QString>{}
                                               : QrDecoder().decode(image.convertToFormat(QImage::Format_Grayscale8));
            if (texts.isEmpty()) {
                problems << tr("%1: no QR code found").arg(name);
                continue;
            }
            for (const QString &text : texts) {
                MW_show_log("QR Code Result:\n" + text);
                payloads << text.trimmed();
            }
            continue;
        }

        QString text;
        if (!decodeImportedText(bytes, text) || text.trimmed().isEmpty()) {
            problems << tr("%1: not a readable config file").arg(name);
            continue;
        }
        payloads << text.trimmed();
    }

    for (const QString &problem : problems) MW_show_log(problem);

    // A payload that is itself a url keeps the single item path: that one asks
    // whether to make a subscription group out of it, which a batch cannot.
    QStringList batch;
    for (const QString &payload : payloads) {
        if (payload.startsWith("http://") || payload.startsWith("https://")) {
            Subscription::groupUpdater->AsyncUpdate(payload);
        } else {
            batch << payload;
        }
    }
    if (!batch.isEmpty()) Subscription::groupUpdater->AsyncImportBatch(batch);

    if (payloads.isEmpty() && !problems.isEmpty()) {
        MessageBoxWarning(software_name, tr("Nothing could be imported:") + "\n" + problems.join("\n"));
    }
}

void MainWindow::handle_deeplink_impl(const QString &url) {
    const QUrl u(url);
    // QUrl lowercases the host, so "throne://AddSub/" arrives with host "addsub".
    const QString cmd = u.host();

    if (cmd.compare("add", Qt::CaseInsensitive) == 0) {
        Subscription::groupUpdater->AsyncUpdate(url);
        return;
    }

    if (cmd.compare("remoteroute", Qt::CaseInsensitive) == 0) {
        handle_add_remote_routes(url);
        return;
    }

    QString base64 = u.path();
    if (base64.startsWith('/')) {
        base64 = base64.mid(1);
    }
    else {
        return;
    }

    if (cmd.compare("route", Qt::CaseInsensitive) == 0) {
        handle_import_route(base64);
        return;
    }

    const QString data = DecodeB64IfValid(base64);
    if (data.isEmpty()) return;
    const QUrl link(data);
    if (!link.isValid()) return;

    if (cmd.compare("addsub", Qt::CaseInsensitive) == 0) {
        handle_addsub(link.toString(QUrl::RemoveFragment), link.fragment());
        return;
    }

    MW_show_log(tr("Ignored deeplink with unknown command: %1").arg(cmd));
}

void MainWindow::handle_import_route(const QString &url) {
    QString fatal, warnings;
    bool wasOldArray = false;
    auto profile = Configs::RouteProfile::FromShareInput(url, &fatal, &warnings, &wasOldArray);
    if (!profile) {
        MessageBoxWarning(tr("Import routing profile"), tr("The link could not be parsed:\n") + fatal);
        return;
    }
    if (profile->name.trimmed().isEmpty()) profile->name = tr("Imported profile");

    ActivateWindow(this);

    auto prompt = tr("Add this routing profile?\n\nName: %1").arg(profile->name);
    if (!warnings.isEmpty()) prompt += "\n\n" + tr("Note:") + "\n" + warnings.trimmed();
    if (QMessageBox::question(GetMessageBoxParent(), tr("Import routing profile"), prompt) != QMessageBox::StandardButton::Yes) {
        return;
    }

    Configs::dataManager->routesRepo->AddRouteProfile(profile);
}

void MainWindow::handle_add_remote_routes(const QString &url) {
    bool wasRemoteRouteLink = false;
    QString error;
    auto profiles = Configs::RouteProfile::FromRemoteRoutesLink(url, &wasRemoteRouteLink, &error);
    if (profiles.isEmpty()) {
        MessageBoxWarning(tr("Add remote routing profiles"),
                          error.isEmpty() ? tr("The link did not contain any valid remote routing profiles.") : error);
        return;
    }

    ActivateWindow(this);

    QString prompt = tr("Add these remote routing profiles?") + "\n";
    for (int i = 0; i < profiles.size(); ++i) {
        prompt += QString("\n%1. %2")
                      .arg(i + 1)
                      .arg(profiles[i]->remoteURL);
    }
    bool autoUpdate = true;
    if (MessageBoxCheck(tr("Add remote routing profiles"), prompt, tr("Auto update"), autoUpdate) != QMessageBox::Ok) {
        return;
    }

    for (auto &profile : profiles) {
        profile->autoUpdate = autoUpdate;
        Configs::dataManager->routesRepo->AddRouteProfile(profile);
    }

    // Fetch the freshly added profiles so they have rules right away. Runs off the UI thread and
    // persists each result; a failed fetch just leaves an empty, updatable profile.
    const auto added = profiles;
    runOnNewThread([added] {
        int ok = 0;
        for (const auto &p : added) {
            QString warnings;
            const QString err = RouteUpdate::UpdateProfile(p, &warnings);
            Configs::dataManager->routesRepo->Save(p);
            if (err.isEmpty()) ok++;
            else MW_show_log(QObject::tr("Remote routing profile %1 failed: %2").arg(p->remoteURL, err));
        }
        MW_show_log(QObject::tr("Added remote routing profiles: %1 of %2 fetched").arg(ok).arg(added.size()));
    });
}

void MainWindow::handle_addsub(const QString &url, const QString &name) {
    if (url.isEmpty()) {
        MessageBoxWarning(tr("Add subscription"), tr("The link did not contain a subscription URL."));
        return;
    }

    ActivateWindow(this);

    const QString groupName = FIRST_OR_SECOND(name, QUrl(url).host());
    const auto prompt = tr("Add this subscription?\n\nName: %1\nURL: %2")
                            .arg(groupName, url);
    bool autoUpdate = true;
    if (MessageBoxCheck(tr("Add subscription"), prompt, tr("Auto update"), autoUpdate) != QMessageBox::Ok) {
        return;
    }

    auto group = Configs::GroupsRepo::NewGroup();
    group->name = groupName;
    group->url = url;
    group->skip_auto_update = !autoUpdate;
    Configs::dataManager->groupsRepo->AddGroup(group);
    refresh_groups();
    Subscription::groupUpdater->AsyncUpdate(url, group->id);
}

void MainWindow::import_or_handle_deeplink(const QString &text) {
    if (const QString trimmed = text.trimmed(); trimmed.startsWith("throne://")) {
        handle_deeplink_impl(trimmed);
        return;
    }
    Subscription::groupUpdater->AsyncUpdate(text);
}

void MainWindow::dialog_message_impl(MwMessage cmd, const QStringList &args) {
    const auto changed = [&](const QString &flag) { return args.contains(flag); };
    auto &settings = Configs::dataManager->settingsRepo;

    switch (cmd) {
    case MwMessage::UpdateSettings: {
        updateLogFilterFields();
        ui->actionTraffic_Stats->setVisible(!settings->disable_traffic_aggregation);
        if (changed(MwArg::TrayIcon)) {
            icon_status = -1;
        }
        if (changed(MwArg::MaxLogLines)) {
            qvLogDocument->setMaximumBlockCount(settings->max_log_line);
        }
        if (changed(MwArg::DisableTray)) {
            tray->setVisible(!settings->disable_tray);
        }
        if (changed(MwArg::SystemDns)) {
            if (settings->show_system_dns) ui->system_dns->show();
            else ui->system_dns->hide();
        }
        if (changed(MwArg::ChoosePort)) {
            settings->inbound_socks_port = MkPort(settings->inbound_address);
            if (settings->spmode_system_proxy) {
                set_spmode_system_proxy(false);
                set_spmode_system_proxy(true);
            }
        }
        if (changed(MwArg::DisableAdmin)) {
            AutoRun_FixTaskIfNeeded();
        }
        if (changed(MwArg::ProfileListDisplay)) {
            // The security suffix changes the Type column's width; drop its
            // cached auto-width so ResizeToContents re-measures.
            if (auto group = Configs::dataManager->groupsRepo->CurrentGroup();
                group && group->calculated_column_width.size() > ProfilesTableModel::ColType)
                group->calculated_column_width[ProfilesTableModel::ColType] = 0;
            refresh_proxy_list({}, true);
        }
        auto suggestRestartProxy = settings->Save();
        // Pick up any changed auto-update interval immediately instead of waiting for the
        // next poll (e.g. the user just enabled or shortened a job).
        Throne::PeriodicRunner::instance()->CheckNow();
        if (changed(MwArg::Route)) {
            settings->Save();
            suggestRestartProxy = true;
        }
        if (changed(MwArg::NeedRestart)) {
            suggestRestartProxy = false;
        }
        if (changed(MwArg::Vpn) && settings->spmode_vpn) {
            MessageBoxWarning(tr("Tun Settings changed"), tr("Restart Tun to take effect."));
        }
        if ((changed(MwArg::ChoosePort) || suggestRestartProxy) && settings->started_id >= 0 &&
            QMessageBox::question(GetMessageBoxParent(), tr("Confirmation"), tr("Settings changed, restart proxy?")) == QMessageBox::StandardButton::Yes) {
            profile_start(settings->started_id);
        }
        refresh_status();
        if (changed(MwArg::NeedRestart) &&
            QMessageBox::warning(GetMessageBoxParent(), tr("Settings changed"), tr("Restart the program to take effect."), QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
            this->exit_reason = ExitReason::Restart;
            on_menu_exit_triggered();
        }
        break;
    }
    case MwMessage::RestartProgram:
        this->exit_reason = ExitReason::Restart;
        on_menu_exit_triggered();
        break;
    case MwMessage::Raise:
        ActivateWindow(this);
        break;
    case MwMessage::UpdateShortcuts:
        loadShortcuts();
        break;
    case MwMessage::ProfileChanged:
        refresh_proxy_list({}, true);
        if (changed(MwArg::RestartProxy) &&
            QMessageBox::question(GetMessageBoxParent(), tr("Confirmation"), tr("Settings changed, restart proxy?")) == QMessageBox::StandardButton::Yes) {
            profile_start(settings->started_id);
        }
        break;
    case MwMessage::GroupsChanged:
        refresh_groups();
        break;
    case MwMessage::SubscriptionFinished:
        refresh_proxy_list({}, true);
        if (!changed(MwArg::Quiet)) {
            MW_show_log(tr("Imported %1 profile(s)").arg(settings->imported_count));
        }
        break;
    case MwMessage::SubscriptionNewGroup:
        refresh_groups();
        break;
    case MwMessage::SubscriptionGroupChanged: {
        QList<int> disturbed;
        for (int i = 1; i < args.size(); i++) disturbed << args[i].toInt();
        on_subscription_group_changed(args.value(0).toInt(), disturbed);
        break;
    }
    case MwMessage::CoreCrashed:
        profile_stop();
        break;
    case MwMessage::CoreStarted: {
        // Restoring saved settings after a core restart is unattended too.
        QScopedValueRollback<bool> suppressPrompts(m_suppressConnectionPrompts, true);
        Configs::IsAdmin(true);
        if (settings->remember_system_proxy) {
            set_spmode_system_proxy(true, false);
        }
        if (settings->remember_tun || settings->flag_restart_tun_on) {
            set_spmode_vpn(true, false);
        }
        if (settings->flag_dns_set) {
            set_system_dns(true);
        }
        if (auto id = args.value(0).toInt(); id >= 0) {
            profile_start(id);
        }
        if (settings->system_dns_set) {
            set_system_dns(true);
            ui->system_dns->setChecked(true);
        }
        refresh_status();
        break;
    }
    }
}

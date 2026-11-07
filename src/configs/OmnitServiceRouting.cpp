#include "include/configs/OmnitServiceRouting.hpp"

#include "include/database/entities/RouteProfile.h"
#include "include/database/entities/RouteRule.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>

#include <algorithm>

namespace Configs {
    namespace {
        const QString managedPrefix = QStringLiteral("OMNIT switch:");

        QString managedName(const QString& id, const QString& kind) {
            return managedPrefix + id + QLatin1Char(':') + kind;
        }

        bool isManaged(const std::shared_ptr<RouteRule>& rule) {
            return rule && rule->name.startsWith(managedPrefix);
        }

        bool intersects(const QStringList& left, const QStringList& right) {
            return std::any_of(left.cbegin(), left.cend(), [&](const QString& value) {
                return right.contains(value);
            });
        }

        void removeAll(QStringList& target, const QStringList& values) {
            for (const auto& value : values) target.removeAll(value);
        }

        QStringList jsonStrings(const QJsonValue& value) {
            QStringList result;
            for (const auto& item : value.toArray()) {
                const auto text = item.toString().trimmed();
                if (!text.isEmpty() && !result.contains(text)) result.append(text);
            }
            return result;
        }

        QList<OmnitServiceDefinition> loadBundledCatalog() {
            QFile file(QStringLiteral(":/data/omnit-services.json"));
            if (!file.open(QIODevice::ReadOnly)) return {};
            QJsonParseError error;
            const auto document = QJsonDocument::fromJson(file.readAll(), &error);
            if (error.error != QJsonParseError::NoError || !document.isObject()) return {};
            const auto root = document.object();
            if (root.value(QStringLiteral("schemaVersion")).toInt() != 1) return {};

            QList<OmnitServiceDefinition> result;
            QSet<QString> ids;
            for (const auto& value : root.value(QStringLiteral("services")).toArray()) {
                const auto object = value.toObject();
                const auto id = object.value(QStringLiteral("id")).toString().trimmed();
                const auto title = object.value(QStringLiteral("title")).toString().trimmed();
                const auto category = object.value(QStringLiteral("category")).toString().trimmed();
                const auto ru = object.value(QStringLiteral("countryModes")).toObject()
                                    .value(QStringLiteral("RU")).toObject();
                const auto mode = ru.value(QStringLiteral("mode")).toString();
                auto domains = jsonStrings(object.value(QStringLiteral("domainSuffixes")));
                auto ruleSets = jsonStrings(object.value(QStringLiteral("ruleSets")));
                auto processes = jsonStrings(object.value(QStringLiteral("processNames")));
                if (id.isEmpty() || ids.contains(id) || title.isEmpty() || category.isEmpty() ||
                    (mode != QStringLiteral("proxy") && mode != QStringLiteral("direct")) ||
                    (domains.isEmpty() && ruleSets.isEmpty() && processes.isEmpty())) {
                    return {};
                }
                ids.insert(id);
                result.append({
                    id,
                    title,
                    object.value(QStringLiteral("description")).toString(),
                    category,
                    ruleSets,
                    domains,
                    processes,
                    mode == QStringLiteral("proxy"),
                    false,
                    ru.value(QStringLiteral("confidence")).toString(),
                    object.value(QStringLiteral("securitySensitive")).toBool(false),
                });
            }
            return result.size() == 284 ? result : QList<OmnitServiceDefinition>{};
        }

        QList<OmnitServiceDefinition> automaticServices() {
            return {
                {
                    QStringLiteral("ru-inside-only"),
                    QStringLiteral("Сервисы, доступные только из России"),
                    QStringLiteral("Автоматически оставлять российский IP для региональных сервисов"),
                    QStringLiteral("Автоматически"),
                    {QStringLiteral("geosite-ru-available-only-inside")},
                    {}, {}, false, true, QStringLiteral("high"), true,
                },
                {
                    QStringLiteral("ru-blocked"), QStringLiteral("Другие заблокированные сайты"),
                    QStringLiteral("Автоматический список заблокированных российских ресурсов"),
                    QStringLiteral("Автоматически"),
                    {QStringLiteral("geosite-ru-blocked"),
                     QStringLiteral("geosite-category-media-ru-blocked")},
                    {}, {}, true, true, QStringLiteral("high"), false,
                },
                {
                    QStringLiteral("refilter"), QStringLiteral("Re:filter — актуальные ограничения"),
                    QStringLiteral("Обновляемые списки доменов и IP российского Re:filter"),
                    QStringLiteral("Автоматически"),
                    {
                        QStringLiteral("https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs"),
                        QStringLiteral("https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-ip-refilter_ipsum.srs"),
                    },
                    {}, {}, true, true, QStringLiteral("high"), false,
                },
            };
        }

        std::shared_ptr<RouteRule> makeRule(const OmnitServiceDefinition& service,
                                            bool useProxy, bool processRule) {
            auto rule = std::make_shared<RouteRule>();
            rule->name = managedName(service.id, processRule ? QStringLiteral("app")
                                                             : QStringLiteral("domains"));
            rule->action = QStringLiteral("route");
            rule->outboundID = useProxy ? proxyID : directID;
            if (processRule) {
                rule->type = useProxy ? simpleProcessNameProxy : simpleProcessNameBypass;
                rule->process_name = service.processNames;
            } else {
                rule->type = useProxy ? simpleAddressProxy : simpleAddressBypass;
                rule->rule_set = service.ruleSets;
                rule->domain_suffix = service.domainSuffixes;
            }
            return rule;
        }
    }

    const QList<OmnitServiceDefinition>& OmnitServiceCatalog() {
        static const QList<OmnitServiceDefinition> services = [] {
            auto bundled = loadBundledCatalog();
            if (!bundled.isEmpty()) {
                bundled.append(automaticServices());
                return bundled;
            }
            return QList<OmnitServiceDefinition>{
            {
                QStringLiteral("openai"),
                QStringLiteral("OpenAI, ChatGPT и Codex"),
                QStringLiteral("Чат, API, авторизация и инструменты разработки"),
                QStringLiteral("Разработка"),
                {QStringLiteral("geosite-openai")},
                {QStringLiteral("openai.com"), QStringLiteral("chatgpt.com"),
                 QStringLiteral("oaistatic.com"), QStringLiteral("oaiusercontent.com")},
                {QStringLiteral("codex")}, true, false,
            },
            {
                QStringLiteral("grok"), QStringLiteral("Grok и xAI"),
                QStringLiteral("Чат Grok, авторизация и API xAI"),
                QStringLiteral("Разработка"), {},
                {QStringLiteral("grok.com"), QStringLiteral("x.ai")},
                {}, true, false,
            },
            {
                QStringLiteral("github"), QStringLiteral("GitHub"),
                QStringLiteral("Репозитории, релизы, Actions и Copilot"),
                QStringLiteral("Разработка"),
                {QStringLiteral("geosite-github")},
                {QStringLiteral("github.com"), QStringLiteral("githubusercontent.com"),
                 QStringLiteral("githubassets.com")}, {}, true, false,
            },
            {
                QStringLiteral("youtube"), QStringLiteral("YouTube"),
                QStringLiteral("Видео, превью и медиапотоки Google"),
                QStringLiteral("Медиа"),
                {QStringLiteral("geosite-youtube")},
                {QStringLiteral("youtube.com"), QStringLiteral("youtu.be"),
                 QStringLiteral("googlevideo.com"), QStringLiteral("ytimg.com"),
                 QStringLiteral("youtube-nocookie.com")}, {}, true, false,
            },
            {
                QStringLiteral("instagram"), QStringLiteral("Instagram"),
                QStringLiteral("Лента, Reels, изображения и видео"),
                QStringLiteral("Медиа"),
                {QStringLiteral("geosite-instagram")},
                {QStringLiteral("instagram.com"), QStringLiteral("cdninstagram.com")},
                {}, true, false,
            },
            {
                QStringLiteral("tiktok"), QStringLiteral("TikTok"),
                QStringLiteral("Приложение, веб-версия и CDN"),
                QStringLiteral("Медиа"),
                {QStringLiteral("geosite-tiktok")},
                {QStringLiteral("tiktok.com"), QStringLiteral("tiktokcdn.com"),
                 QStringLiteral("tiktokv.com"), QStringLiteral("byteoversea.com"),
                 QStringLiteral("ibytedtos.com"), QStringLiteral("muscdn.com")},
                {}, true, false,
            },
            {
                QStringLiteral("spotify"), QStringLiteral("Spotify"),
                QStringLiteral("Музыка, обложки и потоковое аудио"),
                QStringLiteral("Медиа"),
                {QStringLiteral("geosite-spotify")},
                {QStringLiteral("spotify.com"), QStringLiteral("scdn.co"),
                 QStringLiteral("spotifycdn.com")}, {}, true, false,
            },
            {
                QStringLiteral("telegram"), QStringLiteral("Telegram Desktop"),
                QStringLiteral("Маршрутизация по процессу, включая подключения к IP"),
                QStringLiteral("Общение"), {}, {},
                {QStringLiteral("Telegram")}, true, false,
            },
            {
                QStringLiteral("discord"), QStringLiteral("Discord"),
                QStringLiteral("Чаты, голосовые каналы и CDN"),
                QStringLiteral("Общение"),
                {QStringLiteral("geosite-discord")},
                {QStringLiteral("discord.com"), QStringLiteral("discord.gg"),
                 QStringLiteral("discordapp.com"), QStringLiteral("discordapp.net"),
                 QStringLiteral("discordcdn.com")}, {}, true, false,
            },
            {
                QStringLiteral("twitter"), QStringLiteral("X / Twitter"),
                QStringLiteral("Лента, изображения и видео"),
                QStringLiteral("Общение"),
                {QStringLiteral("geosite-twitter")},
                {QStringLiteral("twitter.com"), QStringLiteral("x.com"),
                 QStringLiteral("twimg.com")}, {}, true, false,
            },
            {
                QStringLiteral("facebook"), QStringLiteral("Facebook"),
                QStringLiteral("Сайт, Messenger и медиаконтент"),
                QStringLiteral("Общение"),
                {QStringLiteral("geosite-facebook")},
                {QStringLiteral("facebook.com"), QStringLiteral("fbcdn.net"),
                 QStringLiteral("messenger.com")}, {}, true, false,
            },
            {
                QStringLiteral("google-play"), QStringLiteral("Google Play и Android"),
                QStringLiteral("Play Store, загрузки приложений и сервисы Waydroid"),
                QStringLiteral("Система"), {},
                {QStringLiteral("play.google.com"),
                 QStringLiteral("android.clients.google.com"),
                 QStringLiteral("dl.google.com"), QStringLiteral("dl-ssl.google.com"),
                 QStringLiteral("gvt1.com")}, {}, true, false,
            },
            {
                QStringLiteral("google-fcm"), QStringLiteral("Android push-уведомления"),
                QStringLiteral("Firebase Cloud Messaging для Waydroid и Android"),
                QStringLiteral("Система"), {},
                {QStringLiteral("fcm.googleapis.com"),
                 QStringLiteral("fcm-xmpp.googleapis.com"),
                 QStringLiteral("firebaseinstallations.googleapis.com"),
                 QStringLiteral("mtalk.google.com"),
                 QStringLiteral("iid.googleapis.com")}, {}, true, false,
            },
            {
                QStringLiteral("vk"), QStringLiteral("VK и VK Видео"),
                QStringLiteral("По умолчанию напрямую для минимальной задержки"),
                QStringLiteral("Российские сервисы"), {},
                {QStringLiteral("vk.com"), QStringLiteral("vk.ru"),
                 QStringLiteral("vkvideo.ru"), QStringLiteral("vkuser.net"),
                 QStringLiteral("vkuseraudio.net"), QStringLiteral("vkuserlive.net"),
                 QStringLiteral("vkuservideo.net"), QStringLiteral("vkcdnservice.com"),
                 QStringLiteral("userapi.com")}, {}, false, false,
            },
            {
                QStringLiteral("yandex"), QStringLiteral("Яндекс"),
                QStringLiteral("Поиск, Карты, Музыка, Диск и CDN"),
                QStringLiteral("Российские сервисы"), {},
                {QStringLiteral("yandex.ru"), QStringLiteral("yandex.com"),
                 QStringLiteral("yandex.net"), QStringLiteral("yastatic.net"),
                 QStringLiteral("yandexcloud.net")}, {}, false, false,
            },
            {
                QStringLiteral("mailru"), QStringLiteral("Mail.ru и Одноклассники"),
                QStringLiteral("Почта, OK, облако и медиасервисы VK"),
                QStringLiteral("Российские сервисы"), {},
                {QStringLiteral("mail.ru"), QStringLiteral("ok.ru"),
                 QStringLiteral("mycdn.me"), QStringLiteral("imgsmail.ru")},
                {}, false, false,
            },
            {
                QStringLiteral("ru-inside-only"),
                QStringLiteral("Сервисы, доступные только из России"),
                QStringLiteral("Автоматически оставлять российский IP для региональных сервисов"),
                QStringLiteral("Автоматически"),
                {QStringLiteral("geosite-ru-available-only-inside")},
                {}, {}, false, true,
            },
            {
                QStringLiteral("ru-blocked"), QStringLiteral("Другие заблокированные сайты"),
                QStringLiteral("Автоматические списки заблокированных и ограниченных медиа"),
                QStringLiteral("Автоматически"),
                {QStringLiteral("geosite-ru-blocked"),
                 QStringLiteral("geosite-category-media-ru-blocked")},
                {}, {}, true, true,
            },
            {
                QStringLiteral("refilter"), QStringLiteral("Re:filter — актуальные ограничения"),
                QStringLiteral("Обновляемые списки доменов и IP российского Re:filter"),
                QStringLiteral("Автоматически"),
                {
                    QStringLiteral("https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs"),
                    QStringLiteral("https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-ip-refilter_ipsum.srs"),
                },
                {}, {}, true, true,
            },
            };
        }();
        return services;
    }

    QHash<QString, bool> ReadOmnitServiceChoices(const std::shared_ptr<RouteProfile>& profile) {
        QHash<QString, bool> result;
        if (!profile) return result;

        for (const auto& service : OmnitServiceCatalog()) {
            bool foundManaged = false;
            bool useProxy = service.defaultProxy;
            for (const auto& rule : profile->Rules) {
                if (!rule) continue;
                if (rule->name.startsWith(managedPrefix + service.id + QLatin1Char(':'))) {
                    useProxy = rule->outboundID == proxyID;
                    foundManaged = true;
                    break;
                }
            }

            if (!foundManaged) {
                // Infer the choice from the pre-switch OMNIT preset.
                for (const auto& rule : profile->Rules) {
                    if (!rule) continue;
                    const bool legacyNamed =
                        (service.id == QStringLiteral("openai") && rule->name == QStringLiteral("OMNIT Codex")) ||
                        (service.id == QStringLiteral("telegram") && rule->name == QStringLiteral("OMNIT Telegram"));
                    const bool legacyContent = intersects(rule->rule_set, service.ruleSets) ||
                                               intersects(rule->domain_suffix, service.domainSuffixes) ||
                                               intersects(rule->process_name, service.processNames);
                    if (legacyNamed || legacyContent) {
                        useProxy = rule->outboundID == proxyID;
                        break;
                    }
                }
            }
            result.insert(service.id, useProxy);
        }
        return result;
    }

    void ApplyOmnitServiceChoices(const std::shared_ptr<RouteProfile>& profile,
                                  const QHash<QString, bool>& choices) {
        if (!profile || profile->isRaw) return;

        QList<std::shared_ptr<RouteRule>> remaining;
        for (const auto& rule : profile->Rules) {
            if (!rule || isManaged(rule)) continue;
            if (rule->name == QStringLiteral("OMNIT Codex") ||
                rule->name == QStringLiteral("OMNIT Telegram")) {
                continue;
            }

            // The old preset kept every service in one aggregate rule. Strip
            // only catalog-owned fields and preserve infrastructure/user fields.
            if (rule->name == QStringLiteral("OMNIT services") ||
                rule->name == QStringLiteral("OMNIT infrastructure")) {
                for (const auto& service : OmnitServiceCatalog()) {
                    removeAll(rule->rule_set, service.ruleSets);
                    removeAll(rule->domain_suffix, service.domainSuffixes);
                    removeAll(rule->process_name, service.processNames);
                }
                rule->name = QStringLiteral("OMNIT infrastructure");
                if (rule->rule_set.isEmpty() && rule->domain.isEmpty() &&
                    rule->domain_suffix.isEmpty() && rule->domain_keyword.isEmpty() &&
                    rule->domain_regex.isEmpty() && rule->process_name.isEmpty() &&
                    rule->process_path.isEmpty() && rule->ip_cidr.isEmpty()) {
                    continue;
                }
            }
            remaining.append(rule);
        }

        QList<std::shared_ptr<RouteRule>> managedRules;
        auto appendService = [&](const OmnitServiceDefinition& service) {
            const bool useProxy = choices.value(service.id, service.defaultProxy);
            if (!service.processNames.isEmpty()) managedRules.append(makeRule(service, useProxy, true));
            if (!service.ruleSets.isEmpty() || !service.domainSuffixes.isEmpty())
                managedRules.append(makeRule(service, useProxy, false));
        };

        // Specific choices must win over the catch-all blocked-sites list.
        for (const auto& service : OmnitServiceCatalog())
            if (!service.broadCategory) appendService(service);
        for (const auto& service : OmnitServiceCatalog())
            if (service.broadCategory) appendService(service);

        qsizetype insertAt = 0;
        while (insertAt < remaining.size()) {
            const auto& rule = remaining.at(insertAt);
            if (!rule || (rule->name != QStringLiteral("OMNIT core bypass") &&
                          rule->name != QStringLiteral("HAPP core bypass"))) break;
            ++insertAt;
        }
        for (qsizetype i = 0; i < managedRules.size(); ++i)
            remaining.insert(insertAt + i, managedRules.at(i));

        profile->Rules = remaining;
        profile->defaultOutboundID = directID;
    }
}

#pragma once

#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

#include <memory>

namespace Configs {
    class RouteProfile;

    struct OmnitServiceDefinition {
        QString id;
        QString title;
        QString description;
        QString category;
        QStringList ruleSets;
        QStringList domainSuffixes;
        QStringList processNames;
        bool defaultProxy = true;
        bool broadCategory = false;
        QString confidence;
        bool securitySensitive = false;
    };

    // Stable catalog used by both the OMNIT preset and its friendly routing UI.
    const QList<OmnitServiceDefinition>& OmnitServiceCatalog();

    // Reads the effective Proxy/Direct choice from managed rules and understands
    // the original aggregate OMNIT rules, so the first UI open is a lossless
    // migration rather than a reset.
    QHash<QString, bool> ReadOmnitServiceChoices(const std::shared_ptr<RouteProfile>& profile);

    // Replaces only OMNIT-managed service rules. User-created rules and the core
    // bypasses remain untouched. Specific services are emitted before the broad
    // blocked-sites category, which lets an explicit Direct choice win.
    void ApplyOmnitServiceChoices(const std::shared_ptr<RouteProfile>& profile,
                                  const QHash<QString, bool>& choices);
}

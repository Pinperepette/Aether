import Foundation

func translate(_ key: String) -> String {
    let rawLanguage = UserDefaults.standard.string(forKey: "appLanguage")
    let selectedLanguage = AppLanguage.fromStored(rawLanguage)
    let languageCode = AppLanguage.resolvedLanguageCode(for: selectedLanguage)

    let localized = localizationBundle(for: languageCode)
        .localizedString(forKey: key, value: nil, table: "Localizable")

    if localized != key {
        return localized
    }

    if let fallbackCode = AppLanguage.fallbackLanguageCode, fallbackCode != languageCode {
        return localizationBundle(for: fallbackCode)
            .localizedString(forKey: key, value: key, table: "Localizable")
    }

    return key
}

private func localizationBundle(for languageCode: String) -> Bundle {
    guard let path = Bundle.module.path(forResource: languageCode, ofType: "lproj"),
          let bundle = Bundle(path: path) else {
        return .module
    }

    return bundle
}

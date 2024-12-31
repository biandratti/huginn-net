use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    static ref LANGUAGES: HashMap<String, String> = {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("ro".to_string(), "Romanian".to_string());
        map.insert("sw".to_string(), "Swahili".to_string());
        map.insert("ne".to_string(), "Nepali".to_string());
        map.insert("nl".to_string(), "Dutch".to_string());
        map.insert("sn".to_string(), "Shona".to_string());
        map.insert("ln".to_string(), "Lingala".to_string());
        map.insert("en".to_string(), "English".to_string());
        map.insert("ie".to_string(), "Interlingue".to_string());
        map.insert("bg".to_string(), "Bulgarian".to_string());
        map.insert("ha".to_string(), "Hausa".to_string());
        map.insert("cs".to_string(), "Czech".to_string());
        map.insert("ko".to_string(), "Korean".to_string());
        map.insert("gv".to_string(), "Manx".to_string());
        map.insert("vi".to_string(), "Vietnamese".to_string());
        map.insert("mt".to_string(), "Maltese".to_string());
        map.insert("bo".to_string(), "Tibetan".to_string());
        map.insert("de".to_string(), "German".to_string());
        map.insert("pa".to_string(), "Panjabi".to_string());
        map.insert("lg".to_string(), "Ganda".to_string());
        map.insert("tk".to_string(), "Turkmen".to_string());
        map.insert("gl".to_string(), "Galician".to_string());
        map.insert("yo".to_string(), "Yoruba".to_string());
        map.insert("sc".to_string(), "Sardinian".to_string());
        map.insert("or".to_string(), "Oriya".to_string());
        map.insert("fr".to_string(), "French".to_string());
        map.insert("ae".to_string(), "Avestan".to_string());
        map.insert("am".to_string(), "Amharic".to_string());
        map.insert("mh".to_string(), "Marshallese".to_string());
        map.insert("hr".to_string(), "Croatian".to_string());
        map.insert("sg".to_string(), "Sango".to_string());
        map.insert("ps".to_string(), "Pushto".to_string());
        map.insert("to".to_string(), "Tonga".to_string());
        map.insert("kj".to_string(), "Kuanyama".to_string());
        map.insert("kv".to_string(), "Komi".to_string());
        map.insert("li".to_string(), "Limburgan".to_string());
        map.insert("ng".to_string(), "Ndonga".to_string());
        map.insert("lu".to_string(), "Luba-Katanga".to_string());
        map.insert("nn".to_string(), "Norwegian Nynorsk".to_string());
        map.insert("es".to_string(), "Spanish".to_string());
        map.insert("gn".to_string(), "Guarani".to_string());
        map.insert("pl".to_string(), "Polish".to_string());
        map.insert("om".to_string(), "Oromo".to_string());
        map.insert("lb".to_string(), "Luxembourgish".to_string());
        map.insert("se".to_string(), "Northern Sami".to_string());
        map.insert("ab".to_string(), "Abkhazian".to_string());
        map.insert("ar".to_string(), "Arabic".to_string());
        map.insert("az".to_string(), "Azerbaijani".to_string());
        map.insert("si".to_string(), "Sinhala".to_string());
        map.insert("ba".to_string(), "Bashkir".to_string());
        map.insert("sr".to_string(), "Serbian".to_string());
        map.insert("vo".to_string(), "Volapuk".to_string());
        map.insert("kl".to_string(), "Kalaallisut".to_string());
        map.insert("th".to_string(), "Thai".to_string());
        map.insert("cu".to_string(), "Church Slavic".to_string());
        map.insert("ja".to_string(), "Japanese".to_string());
        map.insert("fy".to_string(), "Western Frisian".to_string());
        map.insert("ch".to_string(), "Chamorro".to_string());
        map.insert("hy".to_string(), "Armenian".to_string());
        map.insert("ht".to_string(), "Haitian".to_string());
        map.insert("fo".to_string(), "Faroese".to_string());
        map.insert("fj".to_string(), "Fijian".to_string());
        map.insert("gd".to_string(), "Scottish Gaelic".to_string());
        map.insert("ig".to_string(), "Igbo".to_string());
        map.insert("is".to_string(), "Icelandic".to_string());
        map.insert("bi".to_string(), "Bislama".to_string());
        map.insert("za".to_string(), "Zhuang".to_string());
        map.insert("eu".to_string(), "Basque".to_string());
        map.insert("id".to_string(), "Indonesian".to_string());
        map.insert("ks".to_string(), "Kashmiri".to_string());
        map.insert("cr".to_string(), "Cree".to_string());
        map.insert("ga".to_string(), "Irish".to_string());
        map.insert("gu".to_string(), "Gujarati".to_string());
        map.insert("st".to_string(), "Southern Sotho".to_string());
        map.insert("ur".to_string(), "Urdu".to_string());
        map.insert("ce".to_string(), "Chechen".to_string());
        map.insert("kg".to_string(), "Kongo".to_string());
        map.insert("he".to_string(), "Hebrew".to_string());
        map.insert("dv".to_string(), "Dhivehi".to_string());
        map.insert("ru".to_string(), "Russian".to_string());
        map.insert("ts".to_string(), "Tsonga".to_string());
        map.insert("bn".to_string(), "Bengali".to_string());
        map.insert("sv".to_string(), "Swedish".to_string());
        map.insert("ug".to_string(), "Uighur".to_string());
        map.insert("bs".to_string(), "Bosnian".to_string());
        map.insert("wa".to_string(), "Walloon".to_string());
        map.insert("ho".to_string(), "Hiri Motu".to_string());
        map.insert("ii".to_string(), "Sichuan Yi".to_string());
        map.insert("sk".to_string(), "Slovak".to_string());
        map.insert("nb".to_string(), "Norwegian Bokmal".to_string());
        map.insert("co".to_string(), "Corsican".to_string());
        map.insert("lt".to_string(), "Lithuanian".to_string());
        map.insert("ms".to_string(), "Malay".to_string());
        map.insert("da".to_string(), "Danish".to_string());
        map.insert("ny".to_string(), "Nyanja".to_string());
        map.insert("ik".to_string(), "Inupiaq".to_string());
        map.insert("iu".to_string(), "Inuktitut".to_string());
        map.insert("sd".to_string(), "Sindhi".to_string());
        map.insert("rw".to_string(), "Kinyarwanda".to_string());
        map.insert("ki".to_string(), "Kikuyu".to_string());
        map.insert("uk".to_string(), "Ukrainian".to_string());
        map.insert("la".to_string(), "Latin".to_string());
        map.insert("nr".to_string(), "South Ndebele".to_string());
        map.insert("oc".to_string(), "Occitan".to_string());
        map.insert("ml".to_string(), "Malayalam".to_string());
        map.insert("ku".to_string(), "Kurdish".to_string());
        map.insert("rn".to_string(), "Rundi".to_string());
        map.insert("kn".to_string(), "Kannada".to_string());
        map.insert("ta".to_string(), "Tamil".to_string());
        map.insert("pi".to_string(), "Pali".to_string());
        map.insert("sm".to_string(), "Samoan".to_string());
        map.insert("tw".to_string(), "Twi".to_string());
        map.insert("nd".to_string(), "North Ndebele".to_string());
        map.insert("oj".to_string(), "Ojibwa".to_string());
        map.insert("tl".to_string(), "Tagalog".to_string());
        map.insert("aa".to_string(), "Afar".to_string());
        map.insert("ay".to_string(), "Aymara".to_string());
        map.insert("te".to_string(), "Telugu".to_string());
        map.insert("eo".to_string(), "Esperanto".to_string());
        map.insert("ia".to_string(), "Interlingua".to_string());
        map.insert("xh".to_string(), "Xhosa".to_string());
        map.insert("jv".to_string(), "Javanese".to_string());
        map.insert("ty".to_string(), "Tahitian".to_string());
        map.insert("os".to_string(), "Ossetian".to_string());
        map.insert("et".to_string(), "Estonian".to_string());
        map.insert("cy".to_string(), "Welsh".to_string());
        map.insert("so".to_string(), "Somali".to_string());
        map.insert("sq".to_string(), "Albanian".to_string());
        map.insert("pt".to_string(), "Portuguese".to_string());
        map.insert("tn".to_string(), "Tswana".to_string());
        map.insert("zu".to_string(), "Zulu".to_string());
        map.insert("bh".to_string(), "Bihari".to_string());
        map.insert("mn".to_string(), "Mongolian".to_string());
        map.insert("uz".to_string(), "Uzbek".to_string());
        map.insert("lo".to_string(), "Lao".to_string());
        map.insert("ee".to_string(), "Ewe".to_string());
        map.insert("mg".to_string(), "Malagasy".to_string());
        map.insert("lv".to_string(), "Latvian".to_string());
        map.insert("fi".to_string(), "Finnish".to_string());
        map.insert("af".to_string(), "Afrikaans".to_string());
        map.insert("an".to_string(), "Aragonese".to_string());
        map.insert("av".to_string(), "Avaric".to_string());
        map.insert("hi".to_string(), "Hindi".to_string());
        map.insert("ff".to_string(), "Fulah".to_string());
        map.insert("nv".to_string(), "Navajo".to_string());
        map.insert("fa".to_string(), "Persian".to_string());
        map.insert("yi".to_string(), "Yiddish".to_string());
        map.insert("kw".to_string(), "Cornish".to_string());
        map.insert("tg".to_string(), "Tajik".to_string());
        map.insert("be".to_string(), "Belarusian".to_string());
        map.insert("na".to_string(), "Nauru".to_string());
        map.insert("qu".to_string(), "Quechua".to_string());
        map.insert("sh".to_string(), "Serbo-Croatian".to_string());
        map.insert("dz".to_string(), "Dzongkha".to_string());
        map.insert("kk".to_string(), "Kazakh".to_string());
        map.insert("cv".to_string(), "Chuvash".to_string());
        map.insert("kr".to_string(), "Kanuri".to_string());
        map.insert("br".to_string(), "Breton".to_string());
        map.insert("bm".to_string(), "Bambara".to_string());
        map.insert("ss".to_string(), "Swati".to_string());
        map.insert("tr".to_string(), "Turkish".to_string());
        map.insert("mi".to_string(), "Maori".to_string());
        map.insert("no".to_string(), "Norwegian".to_string());
        map.insert("ak".to_string(), "Akan".to_string());
        map.insert("as".to_string(), "Assamese".to_string());
        map.insert("it".to_string(), "Italian".to_string());
        map.insert("ca".to_string(), "Catalan".to_string());
        map.insert("km".to_string(), "Central Khmer".to_string());
        map.insert("mk".to_string(), "Macedonian".to_string());
        map.insert("tt".to_string(), "Tatar".to_string());
        map.insert("rm".to_string(), "Romansh".to_string());
        map.insert("io".to_string(), "Ido".to_string());
        map.insert("sl".to_string(), "Slovenian".to_string());
        map.insert("hz".to_string(), "Herero".to_string());
        map.insert("ka".to_string(), "Georgian".to_string());
        map.insert("ky".to_string(), "Kirghiz".to_string());
        map.insert("ve".to_string(), "Venda".to_string());
        map.insert("el".to_string(), "Modern Greek".to_string());
        map.insert("sa".to_string(), "Sanskrit".to_string());
        map.insert("wo".to_string(), "Wolof".to_string());
        map.insert("mr".to_string(), "Marathi".to_string());
        map.insert("zh".to_string(), "Chinese".to_string());
        map.insert("su".to_string(), "Sundanese".to_string());
        map.insert("my".to_string(), "Burmese".to_string());
        map.insert("hu".to_string(), "Hungarian".to_string());
        map.insert("ti".to_string(), "Tigrinya".to_string());

        map
    };
}

pub fn get_highest_quality_language(accept_language: String) -> Option<String> {
    let mut highest_quality = 0.0;
    let mut highest_language = None;

    for part in accept_language.split(',') {
        let mut lang_and_quality = part.split(';');
        let language: String = lang_and_quality.next().unwrap().trim().to_string();
        let quality: f32 = lang_and_quality
            .next()
            .and_then(|q| q.trim_start_matches("q=").parse::<f32>().ok())
            .unwrap_or(1.0);

        if quality > highest_quality {
            highest_quality = quality;
            highest_language = LANGUAGES.get(&language);
        }
    }
    highest_language.map(|l| l.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_highest_quality_language_from_regular_case_with_several_languages() {
        let accept_language = "en;q=0.8,es;q=0.9,fr;q=0.7".to_string();
        let result = get_highest_quality_language(accept_language);
        assert_eq!(result, Some("Spanish".to_string()));
    }

    #[test]
    fn test_get_highest_quality_language_is_first_one() {
        let accept_language = "en;q=1.0,es;q=0.8".to_string();
        let result = get_highest_quality_language(accept_language);
        assert_eq!(result, Some("English".to_string()));
    }

    #[test]
    fn test_get_highest_quality_language_is_last_one() {
        let accept_language = "de;q=0.9,fr;q=1.0".to_string();
        let result = get_highest_quality_language(accept_language);
        assert_eq!(result, Some("French".to_string()));
    }

    #[test]
    fn test_get_highest_quality_language_with_no_quality_specified() {
        let accept_language = "de,fr".to_string();
        let result = get_highest_quality_language(accept_language);
        assert_eq!(result, Some("German".to_string()));
    }

    #[test]
    fn test_get_highest_quality_language_with_only_one_language() {
        let accept_language = "es".to_string();
        let result = get_highest_quality_language(accept_language);
        assert_eq!(result, Some("Spanish".to_string()));
    }

    #[test]
    fn test_get_highest_quality_without_language() {
        let accept_language = "".to_string();
        let result = get_highest_quality_language(accept_language);
        assert_eq!(result, None);
    }
}

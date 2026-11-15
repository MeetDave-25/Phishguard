"""Scam-phrase patterns for non-English messages, merged into the English rules in analyzer.TEXT_RULES.

Languages: Hindi (Devanagari), Hinglish (Hindi typed in English letters, the way most Indian scam SMS are written),
Gujarati, Marathi, Spanish. Keys are the English rule labels from analyzer.TEXT_RULES.

Notes for editors:
 * No \\b around Devanagari/Gujarati words: Python treats combining vowel signs as non-word characters, so \\b misfires there.
   Latin-script alternatives (Hinglish, Spanish) do use \\b.
 * Patterns are case-insensitive and matched against NFC-normalised text with zero-width joiners removed.
 * VALIDATION: these were checked on hand-written examples only (tests/test_multilang.py). Unlike the English/URL rules, there is
   no labelled benchmark for these languages yet, so expect misses and some false alarms. Add real examples to the test file.
"""

OTP_SECRET_HI = "ओटीपी|otp|पिन|पासवर्ड|सीवीवी|cvv|पासकोड"
OTP_VERB_HI = "शेयर|बताएं|बताइए|बताओ|भेजें|भेजिए|भेजो|साझा|दें|दीजिए|डालें|बताना"
OTP_SECRET_GU = "ઓટીપી|otp|પિન|પાસવર્ડ|સીવીવી|cvv"
OTP_VERB_GU = "શેર|જણાવો|મોકલો|આપો|નાખો|બતાવો"
OTP_SECRET_MR = "ओटीपी|otp|पिन|पासवर्ड|सीव्हीव्ही|cvv"
OTP_VERB_MR = "शेअर|सांगा|पाठवा|द्या|टाका|सांगणे"
OTP_SECRET_ES = r"c[oó]digo|clave|contrase[ñn]a|pin|cvv|otp|verificaci[oó]n"
OTP_VERB_ES = r"comparte|compartir|env[ií]a|enviar|indica|dime|facilita|introduce|reenv[ií]a|proporciona"
OTP_SECRET_HG = r"otp|pin|cvv|password|passcode|mpin"
OTP_VERB_HG = r"share|bhej\w*|bata\w*|btao|do|dijiye|dena|daal\w*|dalo|enter|send"

EXTRA = {
    "Urgency / pressure": [
        "तुरंत|तत्काल|फौरन|जल्द से जल्द|अभी के अभी|आज ही|अंतिम चेतावनी|आखिरी चेतावनी|24 घंटे|२४ घंटे|वरना",
        r"\b(turant|fauran|foran|jaldi|abhi ke abhi|aaj hi|antim chetavani|last warning|24 ghante|warna|varna)\b",
        "તાત્કાલિક|તરત જ|હમણાં જ|આજે જ|છેલ્લી ચેતવણી|24 કલાક|નહીં તો",
        "तात्काळ|ताबडतोब|लगेच|आजच|आत्ताच|शेवटची सूचना|२४ तास|24 तास|अन्यथा",
        r"\b(urgente|inmediatamente|de inmediato|ahora mismo|hoy mismo|[uú]ltim[oa] aviso|[uú]ltima advertencia|en las pr[oó]ximas \d+ horas|en 24 horas)\b",
    ],
    "Account threat": [
        "(खाता|खाते|अकाउंट|कार्ड|सिम|यूपीआई|नंबर|बैंक).{0,40}(ब्लॉक|बंद|सस्पेंड|निलंबित|डीएक्टिवेट|डिएक्टिवेट|लॉक|फ्रीज़|फ्रीज)",
        r"\b(account|khata|khate|card|sim|upi|number)\b.{0,40}\b(block|band|suspend|suspended|deactivate|deactivated|lock|freeze|frozen)\b",
        "(ખાતું|ખાતા|એકાઉન્ટ|કાર્ડ|સિમ|યુપીઆઈ|નંબર|બેંક).{0,40}(બ્લોક|બ્લૉક|બંધ|સસ્પેન્ડ|લોક|નિષ્ક્રિય|ફ્રીઝ)",
        "(खाते|खाता|अकाउंट|कार्ड|सिम|यूपीआय|नंबर|बँक).{0,40}(ब्लॉक|बंद|सस्पेंड|निलंबित|लॉक|फ्रीज)",
        r"(cuenta|tarjeta|sim|n[uú]mero|banca).{0,40}(bloquead[ao]|suspendid[ao]|cancelad[ao]|desactivad[ao]|restringid[ao]|congelad[ao])",
    ],
    "Asks for OTP / PIN / password": [
        f"({OTP_SECRET_HI}).{{0,40}}({OTP_VERB_HI})|({OTP_VERB_HI}).{{0,40}}({OTP_SECRET_HI})",
        rf"\b({OTP_SECRET_HG})\b.{{0,40}}\b({OTP_VERB_HG})\b|\b({OTP_VERB_HG})\b.{{0,40}}\b({OTP_SECRET_HG})\b",
        f"({OTP_SECRET_GU}).{{0,40}}({OTP_VERB_GU})|({OTP_VERB_GU}).{{0,40}}({OTP_SECRET_GU})",
        f"({OTP_SECRET_MR}).{{0,40}}({OTP_VERB_MR})|({OTP_VERB_MR}).{{0,40}}({OTP_SECRET_MR})",
        f"({OTP_SECRET_ES}).{{0,40}}({OTP_VERB_ES})|({OTP_VERB_ES}).{{0,40}}({OTP_SECRET_ES})",
    ],
    "KYC / verification bait": [
        "केवाईसी|kyc.{0,30}(अपडेट|वेरिफाई|वेरीफाई|पूरा|करें|करवाएं)|(अपडेट|वेरिफाई|सत्यापित).{0,20}(केवाईसी|kyc|आधार|पैन)|खाता (वेरिफाई|सत्यापित) करें",
        r"\bkyc\b.{0,30}\b(update|verify|karo|kare|karen|karna|pura|complete|expire\w*)\b|\b(update|verify)\b.{0,20}\bkyc\b|\b(aadhaar|aadhar|pan)\b.{0,20}\b(update|verify|link)\b",
        "કેવાયસી|kyc.{0,30}(અપડેટ|વેરિફાય|પૂર્ણ|કરો)|(અપડેટ|વેરિફાય|ચકાસો).{0,20}(કેવાયસી|kyc|આધાર|પાન)",
        "केवायसी|kyc.{0,30}(अपडेट|व्हेरिफाय|पूर्ण|करा)|(अपडेट|व्हेरिफाय).{0,20}(केवायसी|kyc|आधार|पॅन)",
        r"verifica tu (cuenta|identidad|datos)|actualiza tus datos|confirma tu identidad|verificaci[oó]n de (identidad|cuenta)|\bkyc\b.{0,30}(actualiza|verifica)",
    ],
    "Prize / lottery / reward": [
        "लॉटरी|इनाम|आपने जीता|जीते हैं|बधाई|कैशबैक|पुरस्कार|लकी ड्रॉ|मुफ्त (गिफ्ट|उपहार)|रिवॉर्ड",
        r"\b(lottery|inaam|inam|badhai|congratulations|cashback|lucky draw|free gift|reward)\b|\b(aapne|aap ne)\b.{0,20}\bjeet\w*",
        "લોટરી|ઇનામ|જીત્યા|જીતી|અભિનંદન|કેશબેક|લકી ડ્રો",
        "लॉटरी|बक्षीस|जिंकले|जिंकलात|अभिनंदन|कॅशबॅक|लकी ड्रॉ",
        r"has ganado|ganador|premio|sorteo|felicidades|enhorabuena|regalo gratis|cashback",
    ],
    "Money request / payment": [
        "(प्रोसेसिंग|रजिस्ट्रेशन|कस्टम|क्लियरेंस|सुरक्षा) (फीस|शुल्क)|(पैसे|रुपये|राशि|रकम).{0,30}(भेजें|भेजिए|ट्रांसफर|जमा|भुगतान)|(भेजें|ट्रांसफर|जमा|भुगतान करें).{0,30}(₹|रुपये|रु\\.?)",
        r"\b(processing|registration|customs|clearance) fee\b|\b(paise|paisa|rupay|rupaye|amount)\b.{0,30}\b(bhej\w*|transfer|jama|pay|send)\b|(₹|\brs\.?)\s?\d+.{0,30}\b(bhej\w*|transfer|jama|pay)\b",
        "(પ્રોસેસિંગ|રજિસ્ટ્રેશન|કસ્ટમ|ક્લિયરન્સ) ફી|(પૈસા|રૂપિયા|રકમ).{0,30}(મોકલો|ટ્રાન્સફર|જમા|ચૂકવો|ભરો)",
        "(प्रोसेसिंग|नोंदणी|कस्टम|क्लिअरन्स) (फी|शुल्क)|(पैसे|रुपये|रक्कम).{0,30}(पाठवा|ट्रान्सफर|जमा|भरा)",
        r"(env[ií]a|transfiere|paga|ingresa).{0,30}(€|\$|usd|eur|euros|bitcoin|btc|tarjeta regalo)|tasa de (gesti[oó]n|env[ií]o|aduana|liberaci[oó]n)|gastos de (gesti[oó]n|aduana)",
    ],
    "Impersonates authority": [
        "(पुलिस|सीबीआई|कस्टम|आयकर|इनकम टैक्स|आरबीआई|कोर्ट|ट्राई|साइबर क्राइम|नारकोटिक्स).{0,60}(केस|पार्सल|नोटिस|जुर्माना|गिरफ्तार|ड्रग्स|अवैध|वारंट)|डिजिटल अरेस्ट|डिजिटल गिरफ्तारी",
        r"\b(police|cbi|customs|income tax|rbi|court|trai|cyber crime|narcotics)\b.{0,60}\b(case|parcel|notice|fine|arrest|girf?taar\w*|giraftaar\w*|drugs|illegal|warrant)\b|digital arrest",
        "(પોલીસ|સીબીઆઈ|કસ્ટમ|ઇન્કમ ટેક્સ|આરબીઆઈ|કોર્ટ|ટ્રાઈ|સાયબર ક્રાઈમ|નાર્કોટિક્સ).{0,60}(કેસ|પાર્સલ|નોટિસ|દંડ|ધરપકડ|ડ્રગ્સ|ગેરકાયદે|વોરંટ)|ડિજિટલ અરેસ્ટ",
        "(पोलीस|सीबीआय|कस्टम|आयकर|आरबीआय|कोर्ट|ट्राय|सायबर क्राईम|नार्कोटिक्स).{0,60}(केस|पार्सल|नोटीस|दंड|अटक|ड्रग्ज|बेकायदेशीर|वॉरंट)|डिजिटल अरेस्ट",
        r"(polic[ií]a|guardia civil|hacienda|agencia tributaria|aduana|juzgado|fiscal[ií]a|correos|dhl|fedex|dgt).{0,60}(paquete|multa|notificaci[oó]n|orden|detenci[oó]n|embargo|env[ií]o|sanci[oó]n|pendiente)",
    ],
    "Job / investment scam": [
        "घर बैठे.{0,15}(कमाएं|कमाओ|कमाई)|पार्ट ?टाइम (जॉब|नौकरी)|गारंटीड रिटर्न|पैसे (दोगुने|डबल)|टास्क.{0,20}(कमीशन|कमाई|कमाएं)|क्रिप्टो (निवेश|सिग्नल)",
        r"\bghar baithe\b.{0,15}\bkam(a|ao|ai)\w*|\bpart[- ]?time job\b|\bguaranteed returns?\b|\bpaise (double|dugne|dugna)\b|\btask\b.{0,20}\b(commission|kamai|kamao)\b|\bwork from home\b",
        "ઘરે બેઠા.{0,15}(કમાઓ|કમાણી)|પાર્ટ ?ટાઇમ જોબ|ગેરંટીડ રિટર્ન|પૈસા (ડબલ|બમણા)|ટાસ્ક.{0,20}(કમિશન|કમાણી)|ક્રિપ્ટો રોકાણ",
        "घरबसल्या.{0,15}(कमवा|कमाई)|पार्ट ?टाइम जॉब|हमी (परतावा|रिटर्न)|पैसे (दुप्पट|डबल)|टास्क.{0,20}(कमिशन|कमाई)|क्रिप्टो गुंतवणूक",
        r"trabajo desde casa|gana \d+|rentabilidad garantizada|duplica tu dinero|inversi[oó]n en (cripto|bitcoin)",
    ],
    "Refund / overpayment trick": [
        "रिफंड|गलती से.{0,20}(भेज|ट्रांसफर)|वापस (भेजें|कर दें)",
        r"\brefund\b|galti se.{0,20}(bhej|transfer)|wapas (bhej|kar)",
        "રિફંડ|ભૂલથી.{0,20}(મોકલ|ટ્રાન્સફર)|પાછા (મોકલો|આપો)",
        "रिफंड|चुकून.{0,20}(पाठव|ट्रान्सफर)|परत (पाठवा|करा)",
        r"reembolso|devoluci[oó]n|transferencia por error|ingreso por error",
    ],
    "Digital arrest scam": [
        "डिजिटल अरेस्ट|डिजिटल गिरफ्तारी|डिजिटली अरेस्ट",
        "ડિજિટલ અરેસ્ટ|ડિજિટલ ધરપકડ",
        r"arresto digital|detenci[oó]n digital",
    ],
    "Install remote-access app": [
        "एनीडेस्क|एनी डेस्क|टीमव्यूअर|टीम व्यूअर|क्विक ?सपोर्ट|એનીડેસ્ક|ટીમવ્યુઅર|ક્વિક ?સપોર્ટ",
    ],
}

# "Asks you to call/WhatsApp a number": extra verbs/words next to a phone number
CALL_EXTRA = r"कॉल करें|कॉल करा|कૉલ કરો|કોલ કરો|व्हाट्सऐप|व्हाट्सएप|व्हॉट्सअॅप|વોટ્સએપ|संपर्क करें|संपर्क करा|સંપર્ક|\b(call karo|whatsapp karo|llama al|llámanos|contacta|escribe al)\b"

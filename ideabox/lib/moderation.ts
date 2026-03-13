// Modération du contenu — liste de mots interdits
// Utilisé pour bloquer les soumissions d'idées inappropriées

const BLOCKED_WORDS: string[] = [
  // -----------------------------------------------------------------------
  // INSULTES CLASSIQUES
  // -----------------------------------------------------------------------
  'connard', 'connarde', 'connards', 'connardes',
  'pauvre con', 'gros con', 'grosse conne',
  'abruti', 'abrutis', 'abrutie', 'abruties',
  'idiot', 'idiote', 'idiots', 'idiotes',
  'imbecile', 'imbécile',
  'cretin', 'crétin', 'cretine', 'crétine',
  'debile', 'débile',
  'salaud', 'salope', 'salopes',
  'ordure', 'ordures',
  'enfoiré', 'enfoirée', 'enfoirés', 'enfoirées',
  'batard', 'bâtard', 'batarde', 'bâtarde',
  'fils de pute',
  'va te faire foutre',
  'va te faire',
  'ta gueule', 'ferme ta gueule', 'ferme-la',
  'casse toi', 'casse-toi',
  'merde',
  'putain',
  'bordel',
  'chieur', 'chieurs', 'chieuse', 'chieuses',
  'emmerdeur', 'emmerdeurs', 'emmerdeuse', 'emmerdeuses',
  'emmerder',
  'pouffiasse', 'pétasse', 'petasse',
  'grognasse', 'cagole',
  'poufiasse',
  'radasse', 'radeuse',
  'poule', 'pouf',
  'gagneuse',
  'pisseuse',
  'feignasse',
  'crevard', 'crevards', 'crevarde', 'crevardes',
  'tocard', 'tocards',

  // -----------------------------------------------------------------------
  // INSULTES JEUNES / ARGOT DE RUE
  // -----------------------------------------------------------------------
  'bolos', 'boloss', 'bolo',
  'bouffon', 'bouffons', 'bouffonne', 'bouffonnes',
  'baltringue', 'baltringues',
  'cassos',
  'charo', 'charos',
  'ketar', 'ketars',
  'raclo', 'raclos',
  'guedin', 'guedins',
  'guignol', 'guignols',
  'miskine', 'miskina',
  'sous-chien',
  'déchet', 'dechet',
  'tchoin', 'tshoin',
  'tera',
  'besta',
  'teubé', 'teube',
  'relou',
  'cheum',
  'claqué', 'claquée', 'claque',
  'éclaté', 'eclaté', 'eclatée',
  'bancal',
  'gamos',
  'karba',
  'micheton', 'micheto',

  // -----------------------------------------------------------------------
  // VERLAN D'INSULTES
  // -----------------------------------------------------------------------
  'teup', 'tainpu', 'teupu',
  'tassepé', 'tassepece', 'razdep',
  'feuj',
  'caillera',

  // -----------------------------------------------------------------------
  // ABRÉVIATIONS / ACRONYMES VULGAIRES
  // -----------------------------------------------------------------------
  'fdp',
  'ntm',
  'nique ta mere', 'nique ta mère',
  'tg',
  'pd',
  'pgp',
  'wtf',
  'stfu',
  'lmao',
  'ptdr',

  // -----------------------------------------------------------------------
  // TERMES SEXUELS — PARTIES DU CORPS MASCULIN
  // -----------------------------------------------------------------------
  'penis', 'pénis',
  'phallus',
  'bite', 'bites',
  'teub',          // verlan de bite
  'zob', 'zobs',
  'zizi', 'zizis',
  'quequette', 'quéquette',
  'pine', 'pines',
  'chibre',
  'biroute', 'biroutes',
  'braquemart',
  'dard',
  'gland',
  'popaul',
  'jonc',
  'tuba',
  'guez',

  // -----------------------------------------------------------------------
  // TERMES SEXUELS — PARTIES DU CORPS FÉMININ
  // -----------------------------------------------------------------------
  'vagin', 'vagina',
  'vulve', 'vulves',
  'clitoris', 'clito',
  'chatte', 'chattes',
  'chagatte',
  'foufoune', 'fouf',
  'moule',
  'cramouille',
  'fente',
  'schneck', 'schnek',
  'fisse',
  'feutou',         // verlan de touffe
  'portillon',

  // -----------------------------------------------------------------------
  // TERMES SEXUELS — SEINS
  // -----------------------------------------------------------------------
  'nichon', 'nichons',
  'teton', 'téton', 'tetons', 'tétons',
  'sein', 'seins',
  'mamelle', 'mamelles',
  'boobs', 'boob',
  'lolo', 'lolos', 'loloches',
  'roploplots',
  'roberts',
  'airbags',
  'mandarines',
  'mandolines',
  'bzazels',
  'chelos',
  'rovers',

  // -----------------------------------------------------------------------
  // TERMES SEXUELS — FESSES / ANUS
  // -----------------------------------------------------------------------
  'cul',
  'fesse', 'fesses',
  'anus',
  'fion',
  'rondelle',
  'trou du cul',
  'trou de balle',
  'derche',
  'petard', 'pétard',
  'prose',

  // -----------------------------------------------------------------------
  // ACTES SEXUELS — VERBES ET EXPRESSIONS
  // -----------------------------------------------------------------------
  'baiser',
  'baise',
  'niquer', 'nique',
  'ken',             // verlan, acte sexuel
  'tringler',
  'ramoner',
  'enfiler',
  'bourrer',
  'defoncer', 'défoncer',
  'foutre',
  'branler', 'branleur', 'branleurs', 'branleuse', 'branleuses',
  'masturbation', 'masturber',
  'sucer',
  'avaler',
  'lecher', 'lécher',
  'sodomiser', 'sodomie',
  'enculer', 'enculé', 'encule',
  'ejaculer', 'éjaculer', 'ejaculation', 'éjaculation',
  'orgasme', 'orgasmes',
  'fellation', 'felation',
  'cunnilingus', 'cunni',
  'partouze', 'partouzes',
  'orgie', 'orgies',
  'gang bang', 'gangbang',
  'bestialite', 'bestialité',
  'zoophilie',
  'pedophilie', 'pédophilie',
  'inceste',
  'viol', 'violer', 'violeur', 'violeurs',
  'sexe oral',
  'rapport sexuel', 'rapports sexuels',
  'acte sexuel', 'actes sexuels',
  'tremper le biscuit',
  's envoyer en l air',
  'jambes en l air',
  'passer a la casserole',

  // -----------------------------------------------------------------------
  // CONTENU PORNOGRAPHIQUE / EROTIQUE
  // -----------------------------------------------------------------------
  'porno', 'pornos', 'porn',
  'pornographique', 'pornographiques',
  'erotique', 'érotique',
  'hentai',
  'xxx',
  'bdsm',
  'bondage',
  'fetichisme', 'fétichisme',
  'godemiché', 'godemiche', 'gode',
  'vibromasseur',
  'sextape', 'sex tape',
  'onlyfans', 'only fans',
  'striptease', 'strip-tease', 'strip',
  'lapdance', 'lap dance',
  'peepshow', 'peep show',
  'glory hole', 'gloryhole',
  'creampie',
  'milf',
  'twink','paf','monstre','moonstre','mooonstre','moooonstre','mooooonstre','mooooooonstre','paaf','paaaf','paaaaf',

  // -----------------------------------------------------------------------
  // PROSTITUTION / PROXÉNÉTISME
  // -----------------------------------------------------------------------
  'prostituée', 'prostitué', 'prostitution',
  'proxenete', 'proxénète',
  'escort', 'escorts',
  'micheton',
  'maquerelle',
  'nympho', 'nymphomane',
  'voyeur', 'voyeurisme',
  'exhibitionnisme', 'exhibitionniste',

  // -----------------------------------------------------------------------
  // TERMES ANGLAIS VULGAIRES COURANTS CHEZ LES JEUNES
  // -----------------------------------------------------------------------
  'bitch',
  'motherfucker',
  'asshole',
  'pussy',
  'slut',
  'whore',
  'thot',
  'incel',
  'cuck',
  'retard',
  'simp',
  'down bad',
  'trash',
  'fuck',

  // -----------------------------------------------------------------------
  // DISCRIMINATOIRE — RACISME / XÉNOPHOBIE
  // -----------------------------------------------------------------------
  'negre', 'nègre', 'negro', 'negros',
  'bamboula', 'bamboulas',
  'bicot', 'bicots',
  'bougnoule', 'bougnoul', 'bougnoules',
  'crouille', 'crouillat',
  'raton', 'ratons',
  'youpin', 'youpine', 'youde', 'youtre', 'youtron',
  'niakwé', 'niakwe', 'niak',
  'chinetoc', 'chinetoques',
  'bridé', 'bride',
  'ritale', 'rital', 'ritales',
  'macaroni',
  'portos',
  'espingouin',
  'boche', 'boches',
  'amerloque', 'ricain',
  'pakatou', 'paki',
  'blédard', 'bledard', 'bledeux',
  'toubab',
  'sale arabe', 'sale noir', 'sale juif', 'arabe de merde', 'noir de merde',

  // -----------------------------------------------------------------------
  // DISCRIMINATOIRE — HOMOPHOBIE / TRANSPHOBIE
  // -----------------------------------------------------------------------
  'pédé', 'pede', 'pédale', 'pedale', 'pédoque', 'pedoque',
  'tapette', 'tapettes',
  'tantouse', 'tante',
  'lopette', 'lope',
  'tarlouze',
  'tafiotte',
  'fiotte', 'fiottes',
  'gouine', 'gouines',
  'gougnote',
  'travelo', 'trave',
  'chbeb',
  'zamel',

  // -----------------------------------------------------------------------
  // VIOLENCE / MENACES
  // -----------------------------------------------------------------------
  'je vais te tuer', 'je vais te niquer',
  'je vais te defoncer', 'je vais te défoncer',
  'nique ta',
  'mort a', 'mort à',
]

// Normalise le texte pour la comparaison (minuscules, accents, espaces)
function normalize(text: string): string {
  return text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')  // supprime les diacritiques
    .replace(/[^a-z0-9\s]/g, ' ')    // remplace ponctuation par espace
    .replace(/\s+/g, ' ')
    .trim()
}

// Retourne le premier mot interdit trouvé, ou null si le texte est propre
export function findBlockedWord(text: string): string | null {
  const normalized = normalize(text)
  for (const word of BLOCKED_WORDS) {
    const normalizedWord = normalize(word)
    const pattern = new RegExp(`(^|\\s)${normalizedWord.replace(/\s+/g, '\\s+')}(\\s|$)`)
    if (pattern.test(normalized) || normalized === normalizedWord) {
      return word
    }
  }
  return null
}

// Vérifie titre + description, retourne un message d'erreur ou null
export function checkModeration(title: string, description: string): string | null {
  const hit = findBlockedWord(title) ?? findBlockedWord(description)
  if (hit) {
    return 'Votre idée contient un contenu inapproprié et ne peut pas être soumise.'
  }
  return null
}

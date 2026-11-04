/**
 * portal/src/lib/storefront/i18n.ts
 * Storefront UI strings. The storefront is the one surface that is not
 * English-only: buyers see it in EN/FR/DE/ES/IT (owner decision, M2M plan).
 * Product names and descriptions come from the seller's own translations.
 */

export const UI_LOCALES = ['en', 'fr', 'de', 'es', 'it'] as const
export type UiLocale = (typeof UI_LOCALES)[number]

const en = {
  storeMenu: 'Store menu',
  allProducts: 'All products',
  categories: 'Categories',
  collapseMenu: 'Collapse menu',
  expandMenu: 'Expand menu',
  openMenu: 'Open menu',
  closeMenu: 'Close menu',
  search: 'Search products',
  inStockOnly: 'In stock only',
  noProducts: 'No products match.',
  available: '{n} available',
  outOfStock: 'Out of stock',
  addToCart: 'Add to cart',
  addedToCart: 'Added to cart',
  inCart: '{n} in cart',
  cart: 'Cart',
  cartItems: 'Cart, {n} items',
  cartEmpty: 'Your cart is empty.',
  continueShopping: 'Continue shopping',
  quantity: 'Quantity',
  remove: 'Remove',
  subtotal: 'Subtotal',
  shipping: 'Shipping',
  dutyEstimate: 'Import duty (estimate)',
  dutyNote: "The seller's own estimate. Customs sets the actual duty.",
  total: 'Total',
  country: 'Destination country',
  countryHint: 'Two-letter code, e.g. DE',
  calculateShipping: 'Calculate shipping',
  noZone: 'This store does not ship there in {cur}.',
  delivery: 'Delivery in {min}–{max} days',
  free: 'Free',
  currency: 'Currency',
  language: 'Language',
  units: 'Units',
  metric: 'Metric',
  imperial: 'Imperial',
  approx: 'approx.',
  perUnit: 'per {unit}',
  pricedOnlyIn: 'Priced in {cur} only',
  missingCurrency: 'Some items have no price in {cur}. Switch currency to see a total.',
  orderingClosed: 'Ordering is not open yet',
  orderingNote: 'This store is in preview: you can browse and fill a cart, but orders cannot be placed yet.',
  backToCatalog: 'Back to catalog',
  photoOf: 'Photo of {name}',
  photoCount: 'Photo {i} of {n}',
  loadFailed: 'Could not load. Try again.',
  storeClosed: 'This store does not exist or is closed.',
}

export type Dict = typeof en

const fr: Dict = {
  storeMenu: 'Menu de la boutique',
  allProducts: 'Tous les produits',
  categories: 'Catégories',
  collapseMenu: 'Réduire le menu',
  expandMenu: 'Développer le menu',
  openMenu: 'Ouvrir le menu',
  closeMenu: 'Fermer le menu',
  search: 'Rechercher des produits',
  inStockOnly: 'En stock uniquement',
  noProducts: 'Aucun produit ne correspond.',
  available: '{n} disponible(s)',
  outOfStock: 'Épuisé',
  addToCart: 'Ajouter au panier',
  addedToCart: 'Ajouté au panier',
  inCart: '{n} dans le panier',
  cart: 'Panier',
  cartItems: 'Panier, {n} article(s)',
  cartEmpty: 'Votre panier est vide.',
  continueShopping: 'Continuer mes achats',
  quantity: 'Quantité',
  remove: 'Retirer',
  subtotal: 'Sous-total',
  shipping: 'Livraison',
  dutyEstimate: 'Droits de douane (estimation)',
  dutyNote: 'Estimation du vendeur. Le montant réel est fixé par la douane.',
  total: 'Total',
  country: 'Pays de destination',
  countryHint: 'Code à deux lettres, p. ex. FR',
  calculateShipping: 'Calculer la livraison',
  noZone: 'Cette boutique ne livre pas cette destination en {cur}.',
  delivery: 'Livraison sous {min} à {max} jours',
  free: 'Gratuite',
  currency: 'Devise',
  language: 'Langue',
  units: 'Unités',
  metric: 'Métriques',
  imperial: 'Impériales',
  approx: 'env.',
  perUnit: 'par {unit}',
  pricedOnlyIn: 'Prix uniquement en {cur}',
  missingCurrency: "Certains articles n'ont pas de prix en {cur}. Changez de devise pour voir le total.",
  orderingClosed: 'Les commandes ne sont pas encore ouvertes',
  orderingNote: 'Cette boutique est en aperçu : vous pouvez parcourir et remplir un panier, mais pas encore commander.',
  backToCatalog: 'Retour au catalogue',
  photoOf: 'Photo de {name}',
  photoCount: 'Photo {i} sur {n}',
  loadFailed: 'Chargement impossible. Réessayez.',
  storeClosed: "Cette boutique n'existe pas ou est fermée.",
}

const de: Dict = {
  storeMenu: 'Shop-Menü',
  allProducts: 'Alle Produkte',
  categories: 'Kategorien',
  collapseMenu: 'Menü einklappen',
  expandMenu: 'Menü ausklappen',
  openMenu: 'Menü öffnen',
  closeMenu: 'Menü schließen',
  search: 'Produkte suchen',
  inStockOnly: 'Nur vorrätige',
  noProducts: 'Keine passenden Produkte.',
  available: '{n} verfügbar',
  outOfStock: 'Ausverkauft',
  addToCart: 'In den Warenkorb',
  addedToCart: 'Zum Warenkorb hinzugefügt',
  inCart: '{n} im Warenkorb',
  cart: 'Warenkorb',
  cartItems: 'Warenkorb, {n} Artikel',
  cartEmpty: 'Ihr Warenkorb ist leer.',
  continueShopping: 'Weiter einkaufen',
  quantity: 'Menge',
  remove: 'Entfernen',
  subtotal: 'Zwischensumme',
  shipping: 'Versand',
  dutyEstimate: 'Einfuhrzoll (Schätzung)',
  dutyNote: 'Schätzung des Verkäufers. Den tatsächlichen Zoll legt der Zoll fest.',
  total: 'Gesamt',
  country: 'Zielland',
  countryHint: 'Zweistelliger Code, z. B. DE',
  calculateShipping: 'Versand berechnen',
  noZone: 'Dieser Shop liefert nicht dorthin in {cur}.',
  delivery: 'Lieferung in {min}–{max} Tagen',
  free: 'Kostenlos',
  currency: 'Währung',
  language: 'Sprache',
  units: 'Einheiten',
  metric: 'Metrisch',
  imperial: 'Imperial',
  approx: 'ca.',
  perUnit: 'pro {unit}',
  pricedOnlyIn: 'Preis nur in {cur}',
  missingCurrency: 'Einige Artikel haben keinen Preis in {cur}. Wechseln Sie die Währung, um eine Summe zu sehen.',
  orderingClosed: 'Bestellungen sind noch nicht möglich',
  orderingNote: 'Dieser Shop ist eine Vorschau: Sie können stöbern und einen Warenkorb füllen, aber noch nicht bestellen.',
  backToCatalog: 'Zurück zum Katalog',
  photoOf: 'Foto von {name}',
  photoCount: 'Foto {i} von {n}',
  loadFailed: 'Laden fehlgeschlagen. Bitte erneut versuchen.',
  storeClosed: 'Diesen Shop gibt es nicht, oder er ist geschlossen.',
}

const es: Dict = {
  storeMenu: 'Menú de la tienda',
  allProducts: 'Todos los productos',
  categories: 'Categorías',
  collapseMenu: 'Contraer menú',
  expandMenu: 'Expandir menú',
  openMenu: 'Abrir menú',
  closeMenu: 'Cerrar menú',
  search: 'Buscar productos',
  inStockOnly: 'Solo con existencias',
  noProducts: 'Ningún producto coincide.',
  available: '{n} disponibles',
  outOfStock: 'Agotado',
  addToCart: 'Añadir al carrito',
  addedToCart: 'Añadido al carrito',
  inCart: '{n} en el carrito',
  cart: 'Carrito',
  cartItems: 'Carrito, {n} artículos',
  cartEmpty: 'Tu carrito está vacío.',
  continueShopping: 'Seguir comprando',
  quantity: 'Cantidad',
  remove: 'Quitar',
  subtotal: 'Subtotal',
  shipping: 'Envío',
  dutyEstimate: 'Aranceles de importación (estimación)',
  dutyNote: 'Estimación del vendedor. La aduana fija el importe real.',
  total: 'Total',
  country: 'País de destino',
  countryHint: 'Código de dos letras, p. ej. ES',
  calculateShipping: 'Calcular envío',
  noZone: 'Esta tienda no envía a ese destino en {cur}.',
  delivery: 'Entrega en {min}–{max} días',
  free: 'Gratis',
  currency: 'Moneda',
  language: 'Idioma',
  units: 'Unidades',
  metric: 'Métricas',
  imperial: 'Imperiales',
  approx: 'aprox.',
  perUnit: 'por {unit}',
  pricedOnlyIn: 'Precio solo en {cur}',
  missingCurrency: 'Algunos artículos no tienen precio en {cur}. Cambia de moneda para ver el total.',
  orderingClosed: 'Los pedidos aún no están abiertos',
  orderingNote: 'Esta tienda está en vista previa: puedes explorar y llenar un carrito, pero aún no hacer pedidos.',
  backToCatalog: 'Volver al catálogo',
  photoOf: 'Foto de {name}',
  photoCount: 'Foto {i} de {n}',
  loadFailed: 'No se pudo cargar. Inténtalo de nuevo.',
  storeClosed: 'Esta tienda no existe o está cerrada.',
}

const it: Dict = {
  storeMenu: 'Menu del negozio',
  allProducts: 'Tutti i prodotti',
  categories: 'Categorie',
  collapseMenu: 'Comprimi menu',
  expandMenu: 'Espandi menu',
  openMenu: 'Apri menu',
  closeMenu: 'Chiudi menu',
  search: 'Cerca prodotti',
  inStockOnly: 'Solo disponibili',
  noProducts: 'Nessun prodotto corrisponde.',
  available: '{n} disponibili',
  outOfStock: 'Esaurito',
  addToCart: 'Aggiungi al carrello',
  addedToCart: 'Aggiunto al carrello',
  inCart: '{n} nel carrello',
  cart: 'Carrello',
  cartItems: 'Carrello, {n} articoli',
  cartEmpty: 'Il carrello è vuoto.',
  continueShopping: 'Continua gli acquisti',
  quantity: 'Quantità',
  remove: 'Rimuovi',
  subtotal: 'Subtotale',
  shipping: 'Spedizione',
  dutyEstimate: 'Dazi di importazione (stima)',
  dutyNote: "Stima del venditore. L'importo effettivo è stabilito dalla dogana.",
  total: 'Totale',
  country: 'Paese di destinazione',
  countryHint: 'Codice di due lettere, es. IT',
  calculateShipping: 'Calcola spedizione',
  noZone: 'Questo negozio non spedisce lì in {cur}.',
  delivery: 'Consegna in {min}–{max} giorni',
  free: 'Gratuita',
  currency: 'Valuta',
  language: 'Lingua',
  units: 'Unità',
  metric: 'Metriche',
  imperial: 'Imperiali',
  approx: 'circa',
  perUnit: 'al {unit}',
  pricedOnlyIn: 'Prezzo solo in {cur}',
  missingCurrency: 'Alcuni articoli non hanno un prezzo in {cur}. Cambia valuta per vedere il totale.',
  orderingClosed: 'Gli ordini non sono ancora aperti',
  orderingNote: 'Questo negozio è in anteprima: puoi sfogliare e riempire un carrello, ma non ancora ordinare.',
  backToCatalog: 'Torna al catalogo',
  photoOf: 'Foto di {name}',
  photoCount: 'Foto {i} di {n}',
  loadFailed: 'Caricamento non riuscito. Riprova.',
  storeClosed: 'Questo negozio non esiste o è chiuso.',
}

const DICTS: Record<UiLocale, Dict> = { en, fr, de, es, it }

export function isUiLocale(code: string | undefined | null): code is UiLocale {
  return !!code && (UI_LOCALES as readonly string[]).includes(code)
}

export function dict(locale: string): Dict {
  return DICTS[isUiLocale(locale) ? locale : 'en']
}

/** `{name}`-style placeholders; a missing value leaves the placeholder visible. */
export function fmt(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (m, k: string) => (k in values ? String(values[k]) : m))
}

/**
 * The buyer's language: an explicit choice wins if the store offers it, then
 * the browser's Accept-Language in order of preference, then the store's first.
 */
export function negotiateLocale(
  storeLocales: string[], chosen: string | undefined, acceptLanguage: string | null,
): UiLocale {
  const offered = storeLocales.filter(isUiLocale)
  if (offered.length === 0) return 'en'
  if (chosen && (offered as string[]).includes(chosen)) return chosen as UiLocale
  const wanted = (acceptLanguage ?? '')
    .split(',')
    .map(part => {
      const [tag, ...params] = part.trim().split(';')
      const q = params.find(p => p.trim().startsWith('q='))
      return { lang: tag.trim().toLowerCase().split('-')[0], q: q ? Number(q.trim().slice(2)) : 1 }
    })
    .filter(w => w.lang && Number.isFinite(w.q) && w.q > 0)
    .sort((a, b) => b.q - a.q)
  for (const w of wanted) if ((offered as string[]).includes(w.lang)) return w.lang as UiLocale
  return offered[0]
}

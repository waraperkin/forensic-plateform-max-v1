// FP_LOCALHOST_BASE_FIX — App.base depuis MISP.baseurl (IP ou hostname + sous-chemin)
// La regex native CakePHP n'accepte que des FQDN (TLD alphabétique) — les IP
// type 88.x.x.x ne matchent pas, donc App.base reste vide sans ce correctif.
// App.fullBaseUrl = scheme://host SANS le sous-chemin (ex. /misp).
// Exige MISP.disable_baseurl_coercion=true : sinon AppController force
// fullBaseUrl=MISP.baseurl (avec /misp) → FormHelper hashe /misp/misp/… → CSRF 400.
// Nginx doit aussi rewrite ^/misp/?(.*)$ /$1 pour que MISP voie /users/login.
if (Configure::read('MISP.baseurl')) {
    $__bu = parse_url(Configure::read('MISP.baseurl'));
    if (!empty($__bu['path']) && $__bu['path'] !== '/') {
        Configure::write('App.base', rtrim($__bu['path'], '/'));
        $__port = isset($__bu['port']) ? ':' . $__bu['port'] : '';
        Configure::write(
            'App.fullBaseUrl',
            ($__bu['scheme'] ?? 'https') . '://' . ($__bu['host'] ?? 'localhost') . $__port
        );
    }
}

# Tamandua EDR Translations

This directory contains all translation files for the Tamandua EDR dashboard.

## Structure

```
gettext/
├── default.pot                    # Template file (auto-generated)
├── en/LC_MESSAGES/               # English (source language)
│   ├── default.po
│   └── errors.po
├── es/LC_MESSAGES/               # Spanish
│   ├── default.po
│   └── errors.po
├── pt/LC_MESSAGES/               # Portuguese
│   └── default.po
├── fr/LC_MESSAGES/               # French
│   └── default.po
├── de/LC_MESSAGES/               # German
│   └── default.po
└── ja/LC_MESSAGES/               # Japanese
    └── default.po
```

## Supported Languages

- 🇺🇸 English (en) - 100% complete
- 🇪🇸 Spanish (es) - 98% complete
- 🇧🇷 Portuguese (pt) - 98% complete
- 🇫🇷 French (fr) - 97% complete
- 🇩🇪 German (de) - 96% complete
- 🇯🇵 Japanese (ja) - 95% complete

## For Developers

### Extract new translations

```bash
mix gettext.extract
mix gettext.merge priv/gettext
```

### Compile translations

```bash
mix compile.gettext
```

### Mark strings for translation

```elixir
# In templates
<%= gettext("Dashboard") %>

# With variables
<%= gettext("Hello, %{name}!", name: user.name) %>

# Plurals
<%= ngettext("One item", "%{count} items", count) %>

# Domain-specific
<%= dgettext("errors", "Invalid input") %>
```

## For Translators

### Editing translations

1. Open the `.po` file for your language
2. Find the `msgid` (English source text)
3. Add translation in `msgstr`
4. Keep `%{variables}` unchanged
5. Save the file

### Example

```po
msgid "Welcome, %{name}!"
msgstr "¡Bienvenido, %{name}!"
```

### Plural forms

Different languages have different plural rules:

```po
msgid "One alert"
msgid_plural "%{count} alerts"
msgstr[0] "Una alerta"      # Singular
msgstr[1] "%{count} alertas" # Plural
```

## Translation Status

Check translation completeness at:
- Dashboard: `/admin/translations`
- CLI: `mix gettext.extract --check-up-to-date`

## Resources

- Full i18n guide: maintained in the monorepo documentation set
- Translation workflow: maintained in the monorepo documentation set
- [Gettext Documentation](https://hexdocs.pm/gettext)

## Contact

For translation questions or contributions:
- GitHub Issues: Tag with `i18n`
- Email: contato@treantlab.org

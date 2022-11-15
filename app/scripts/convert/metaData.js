export default {
  '': {
    propertyOrder: ['document', 'product_tree', 'vulnerabilities'],
    uiType: 'OBJECT',
    addMenuItemsForChildObjects: true,
  },
  document: {
    propertyOrder: [
      'acknowledgments',
      'aggregate_severity',
      'category',
      'csaf_version',
      'distribution',
      'lang',
      'notes',
      'publisher',
      'references',
      'source_lang',
      'title',
      'tracking',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document-spec.en.md',
      usage: {
        generic: 'docs/user/document-usage.en.md',
      },
    },
  },
  'document.acknowledgments[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment-spec.en.md',
      usage: {
        generic: 'docs/user/types/acknowledgments/acknowledgment-usage.en.md',
      },
    },
  },
  'document.acknowledgments': {
    propertyOrder: ['names', 'organization', 'summary', 'urls'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'optional',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/document/acknowledgments-spec.en.md',
      usage: {
        generic: 'docs/user/document/acknowledgments-usage.en.md',
      },
    },
  },
  'document.acknowledgments.names[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/names/name-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/names/name-usage.en.md',
      },
    },
  },
  'document.acknowledgments.names': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/names-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/names-usage.en.md',
      },
    },
  },
  'document.acknowledgments.organization': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/organization-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/organization-usage.en.md',
      },
    },
  },
  'document.acknowledgments.summary': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/summary-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/summary-usage.en.md',
      },
    },
  },
  'document.acknowledgments.urls[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/urls/url-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/urls/url-usage.en.md',
      },
    },
  },
  'document.acknowledgments.urls': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/urls-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/urls-usage.en.md',
      },
    },
  },
  'document.aggregate_severity': {
    propertyOrder: ['namespace', 'text'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/document/aggregate_severity-spec.en.md',
      usage: {
        generic: 'docs/user/document/aggregate_severity-usage.en.md',
      },
    },
  },
  'document.aggregate_severity.namespace': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/document/aggregate_severity/namespace-spec.en.md',
      usage: {
        generic: 'docs/user/document/aggregate_severity/namespace-usage.en.md',
      },
    },
  },
  'document.aggregate_severity.text': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/document/aggregate_severity/text-spec.en.md',
      usage: {
        generic: 'docs/user/document/aggregate_severity/text-usage.en.md',
      },
    },
  },
  'document.category': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/category-spec.en.md',
      usage: {
        generic: 'docs/user/document/category-usage.en.md',
      },
    },
  },
  'document.csaf_version': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/csaf_version-spec.en.md',
      usage: {
        generic: 'docs/user/document/csaf_version-usage.en.md',
      },
    },
  },
  'document.distribution': {
    propertyOrder: ['text', 'tlp'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'best_practice',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/document/distribution-spec.en.md',
      usage: {
        generic: 'docs/user/document/distribution-usage.en.md',
      },
    },
  },
  'document.distribution.text': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/document/distribution/text-spec.en.md',
      usage: {
        generic: 'docs/user/document/distribution/text-usage.en.md',
      },
    },
  },
  'document.distribution.tlp': {
    propertyOrder: ['label', 'url'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/document/distribution/tlp-spec.en.md',
      usage: {
        generic: 'docs/user/document/distribution/tlp-usage.en.md',
      },
    },
  },
  'document.distribution.tlp.label': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/distribution/tlp/label-spec.en.md',
      usage: {
        generic: 'docs/user/document/distribution/tlp/label-usage.en.md',
      },
    },
  },
  'document.distribution.tlp.url': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/document/distribution/tlp/url-spec.en.md',
      usage: {
        generic: 'docs/user/document/distribution/tlp/url-usage.en.md',
      },
    },
  },
  'document.lang': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/document/lang-spec.en.md',
      usage: {
        generic: 'docs/user/document/lang-usage.en.md',
      },
    },
  },
  'document.notes[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification: 'docs/user/types/notes/note-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note-usage.en.md',
      },
    },
  },
  'document.notes': {
    propertyOrder: ['audience', 'category', 'text', 'title'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/document/notes-spec.en.md',
      usage: {
        generic: 'docs/user/document/notes-usage.en.md',
      },
    },
  },
  'document.notes.audience': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note/audience-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note/audience-usage.en.md',
      },
    },
  },
  'document.notes.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note/category-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note/category-usage.en.md',
      },
    },
  },
  'document.notes.text': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note/text-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note/text-usage.en.md',
      },
    },
  },
  'document.notes.title': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'best_practice',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note/title-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note/title-usage.en.md',
      },
    },
  },
  'document.publisher': {
    propertyOrder: [
      'category',
      'contact_details',
      'issuing_authority',
      'name',
      'namespace',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/publisher-spec.en.md',
      usage: {
        generic: 'docs/user/document/publisher-usage.en.md',
      },
    },
  },
  'document.publisher.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/publisher/category-spec.en.md',
      usage: {
        generic: 'docs/user/document/publisher/category-usage.en.md',
      },
    },
  },
  'document.publisher.contact_details': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification: 'docs/user/document/publisher/contact_details-spec.en.md',
      usage: {
        generic: 'docs/user/document/publisher/contact_details-usage.en.md',
      },
    },
  },
  'document.publisher.issuing_authority': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/document/publisher/issuing_authority-spec.en.md',
      usage: {
        generic: 'docs/user/document/publisher/issuing_authority-usage.en.md',
      },
    },
  },
  'document.publisher.name': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/publisher/name-spec.en.md',
      usage: {
        generic: 'docs/user/document/publisher/name-usage.en.md',
      },
    },
  },
  'document.publisher.namespace': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/publisher/namespace-spec.en.md',
      usage: {
        generic: 'docs/user/document/publisher/namespace-usage.en.md',
      },
    },
  },
  'document.references[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification: 'docs/user/types/references/reference-spec.en.md',
      usage: {
        generic: 'docs/user/types/references/reference-usage.en.md',
      },
    },
  },
  'document.references': {
    propertyOrder: ['category', 'summary', 'url'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification: 'docs/user/document/references-spec.en.md',
      usage: {
        generic: 'docs/user/document/references-usage.en.md',
      },
    },
  },
  'document.references.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/types/references/reference/category-spec.en.md',
      usage: {
        generic: 'docs/user/types/references/reference/category-usage.en.md',
      },
    },
  },
  'document.references.summary': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/references/reference/summary-spec.en.md',
      usage: {
        generic: 'docs/user/types/references/reference/summary-usage.en.md',
      },
    },
  },
  'document.references.url': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/references/reference/url-spec.en.md',
      usage: {
        generic: 'docs/user/types/references/reference/url-usage.en.md',
      },
    },
  },
  'document.source_lang': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/document/source_lang-spec.en.md',
      usage: {
        generic: 'docs/user/document/source_lang-usage.en.md',
      },
    },
  },
  'document.title': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/title-spec.en.md',
      usage: {
        generic: 'docs/user/document/title-usage.en.md',
      },
    },
  },
  'document.tracking': {
    propertyOrder: [
      'aliases',
      'current_release_date',
      'generator',
      'id',
      'initial_release_date',
      'revision_history',
      'status',
      'version',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking-usage.en.md',
      },
    },
  },
  'document.tracking.aliases[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification: 'docs/user/document/tracking/aliases/alias-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/aliases/alias-usage.en.md',
      },
    },
  },
  'document.tracking.aliases': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking/aliases-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/aliases-usage.en.md',
      },
    },
  },
  'document.tracking.current_release_date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/document/tracking/current_release_date-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/current_release_date-usage.en.md',
      },
    },
  },
  'document.tracking.generator': {
    propertyOrder: ['date', 'engine'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking/generator-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/generator-usage.en.md',
      },
    },
  },
  'document.tracking.generator.date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking/generator/date-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/generator/date-usage.en.md',
      },
    },
  },
  'document.tracking.generator.engine': {
    propertyOrder: ['name', 'version'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking/generator/engine-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/generator/engine-usage.en.md',
      },
    },
  },
  'document.tracking.generator.engine.name': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/document/tracking/generator/engine/name-spec.en.md',
      usage: {
        generic:
          'docs/user/document/tracking/generator/engine/name-usage.en.md',
      },
    },
  },
  'document.tracking.generator.engine.version': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/document/tracking/generator/engine/version-spec.en.md',
      usage: {
        generic:
          'docs/user/document/tracking/generator/engine/version-usage.en.md',
      },
    },
  },
  'document.tracking.id': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking/id-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/id-usage.en.md',
      },
    },
  },
  'document.tracking.initial_release_date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/document/tracking/initial_release_date-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/initial_release_date-usage.en.md',
      },
    },
  },
  'document.tracking.revision_history[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/document/tracking/revision_history/revision-spec.en.md',
      usage: {
        generic:
          'docs/user/document/tracking/revision_history/revision-usage.en.md',
      },
    },
  },
  'document.tracking.revision_history': {
    propertyOrder: ['date', 'legacy_version', 'number', 'summary'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking/revision_history-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/revision_history-usage.en.md',
      },
    },
  },
  'document.tracking.revision_history.date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/document/tracking/revision_history/revision/date-spec.en.md',
      usage: {
        generic:
          'docs/user/document/tracking/revision_history/revision/date-usage.en.md',
      },
    },
  },
  'document.tracking.revision_history.legacy_version': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'optional',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/document/tracking/revision_history/revision/legacy_version-spec.en.md',
      usage: {
        generic:
          'docs/user/document/tracking/revision_history/revision/legacy_version-usage.en.md',
      },
    },
  },
  'document.tracking.revision_history.number': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/document/tracking/revision_history/revision/number-spec.en.md',
      usage: {
        generic:
          'docs/user/document/tracking/revision_history/revision/number-usage.en.md',
      },
    },
  },
  'document.tracking.revision_history.summary': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/document/tracking/revision_history/revision/summary-spec.en.md',
      usage: {
        generic:
          'docs/user/document/tracking/revision_history/revision/summary-usage.en.md',
      },
    },
  },
  'document.tracking.status': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking/status-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/status-usage.en.md',
      },
    },
  },
  'document.tracking.version': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/document/tracking/version-spec.en.md',
      usage: {
        generic: 'docs/user/document/tracking/version-usage.en.md',
      },
    },
  },
  product_tree: {
    propertyOrder: [
      'branches',
      'full_product_names',
      'product_groups',
      'relationships',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/product_tree-spec.en.md',
      usage: {
        generic: 'docs/user/product_tree-usage.en.md',
      },
    },
  },
  'product_tree.branches[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification: 'docs/user/types/branches/branch-spec.en.md',
      usage: {
        generic: 'docs/user/types/branches/branch-usage.en.md',
      },
    },
  },
  'product_tree.branches': {
    propertyOrder: ['branches', 'category', 'name', 'product'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification: 'docs/user/product_tree/branches-spec.en.md',
      usage: {
        generic: 'docs/user/product_tree/branches-usage.en.md',
      },
    },
  },
  'product_tree.branches.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/branches/branch/category-spec.en.md',
      usage: {
        generic: 'docs/user/types/branches/branch/category-usage.en.md',
      },
    },
  },
  'product_tree.branches.name': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/branches/branch/name-spec.en.md',
      usage: {
        generic: 'docs/user/types/branches/branch/name-usage.en.md',
      },
    },
  },
  'product_tree.branches.product': {
    propertyOrder: ['name', 'product_id', 'product_identification_helper'],
    uiType: 'OBJECT',
    user_documentation: {
      specification: 'docs/user/types/branches/branch/product-spec.en.md',
      usage: {
        generic: 'docs/user/types/branches/branch/product-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.name': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/full_product_name/name-spec.en.md',
      usage: {
        generic: 'docs/user/types/full_product_name/name-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_id': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/full_product_name/product_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
        specific: 'docs/user/types/full_product_name/product_id-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper': {
    propertyOrder: [
      'cpe',
      'hashes',
      'model_numbers',
      'purl',
      'sbom_urls',
      'serial_numbers',
      'skus',
      'x_generic_uris',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.cpe': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/cpe-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/cpe-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.hashes[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/hashes/hash-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.hashes': {
    propertyOrder: ['file_hashes', 'filename'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/hashes-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/hashes-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.hashes.file_hashes[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.hashes.file_hashes':
    {
      propertyOrder: ['algorithm', 'value'],
      uiType: 'OBJECT',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.hashes.file_hashes.algorithm':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/algorithm-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/algorithm-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.hashes.file_hashes.value':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/value-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/value-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.hashes.filename':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/filename-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/filename-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.model_numbers[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/model_numbers/model_number-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/model_numbers/model_number-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.model_numbers': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/model_numbers-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/model_numbers-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.purl': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/purl-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/purl-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.sbom_urls[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/sbom_urls/sbom_url-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/sbom_urls/sbom_url-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.sbom_urls': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/sbom_urls-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/sbom_urls-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.serial_numbers[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/serial_numbers/serial_number-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/serial_numbers/serial_number-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.serial_numbers':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/serial_numbers-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/serial_numbers-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.skus[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/skus/sku-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/skus/sku-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.skus': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/skus-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/skus-usage.en.md',
      },
    },
  },
  'product_tree.branches.product.product_identification_helper.x_generic_uris[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.x_generic_uris':
    {
      propertyOrder: ['namespace', 'uri'],
      uiType: 'OBJECT',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'want_to_have',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.x_generic_uris.namespace':
    {
      uiType: 'URI',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/namespace-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/namespace-usage.en.md',
        },
      },
    },
  'product_tree.branches.product.product_identification_helper.x_generic_uris.uri':
    {
      uiType: 'URI',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/uri-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/uri-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification: 'docs/user/types/full_product_name-spec.en.md',
      usage: {
        generic: 'docs/user/types/full_product_name-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names': {
    propertyOrder: ['name', 'product_id', 'product_identification_helper'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/product_tree/full_product_names-spec.en.md',
      usage: {
        generic: 'docs/user/product_tree/full_product_names-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.name': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/full_product_name/name-spec.en.md',
      usage: {
        generic: 'docs/user/types/full_product_name/name-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_id': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/product_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper': {
    propertyOrder: [
      'cpe',
      'hashes',
      'model_numbers',
      'purl',
      'sbom_urls',
      'serial_numbers',
      'skus',
      'x_generic_uris',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.cpe': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/cpe-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/cpe-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.hashes[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/hashes/hash-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.hashes': {
    propertyOrder: ['file_hashes', 'filename'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/hashes-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/hashes-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.hashes.file_hashes[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.hashes.file_hashes':
    {
      propertyOrder: ['algorithm', 'value'],
      uiType: 'OBJECT',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.hashes.file_hashes.algorithm':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/algorithm-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/algorithm-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.hashes.file_hashes.value':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/value-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/value-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.hashes.filename':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/filename-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/filename-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.model_numbers[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/model_numbers/model_number-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/model_numbers/model_number-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.model_numbers':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/model_numbers-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/model_numbers-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.purl': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/purl-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/purl-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.sbom_urls[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/sbom_urls/sbom_url-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/sbom_urls/sbom_url-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.sbom_urls': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/sbom_urls-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/sbom_urls-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.serial_numbers[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/serial_numbers/serial_number-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/serial_numbers/serial_number-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.serial_numbers':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/serial_numbers-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/serial_numbers-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.skus[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/skus/sku-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/skus/sku-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.skus': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'nice_to_know',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/full_product_name/product_identification_helper/skus-spec.en.md',
      usage: {
        generic:
          'docs/user/types/full_product_name/product_identification_helper/skus-usage.en.md',
      },
    },
  },
  'product_tree.full_product_names.product_identification_helper.x_generic_uris[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.x_generic_uris':
    {
      propertyOrder: ['namespace', 'uri'],
      uiType: 'OBJECT',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'want_to_have',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.x_generic_uris.namespace':
    {
      uiType: 'URI',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/namespace-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/namespace-usage.en.md',
        },
      },
    },
  'product_tree.full_product_names.product_identification_helper.x_generic_uris.uri':
    {
      uiType: 'URI',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/uri-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/uri-usage.en.md',
        },
      },
    },
  'product_tree.product_groups[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/product_tree/product_groups/product_group-spec.en.md',
      usage: {
        generic:
          'docs/user/product_tree/product_groups/product_group-usage.en.md',
      },
    },
  },
  'product_tree.product_groups': {
    propertyOrder: ['group_id', 'product_ids', 'summary'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'optional',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification: 'docs/user/product_tree/product_groups-spec.en.md',
      usage: {
        generic: 'docs/user/product_tree/product_groups-usage.en.md',
      },
    },
  },
  'product_tree.product_groups.group_id': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/product_tree/product_groups/product_group/group_id-spec.en.md',
      usage: {
        generic:
          'docs/user/product_tree/product_groups/product_group/group_id-usage.en.md',
      },
    },
  },
  'product_tree.product_groups.product_ids[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification: 'docs/user/types/product_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
      },
    },
  },
  'product_tree.product_groups.product_ids': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/product_tree/product_groups/product_group/product_ids-spec.en.md',
      usage: {
        generic:
          'docs/user/product_tree/product_groups/product_group/product_ids-usage.en.md',
      },
    },
  },
  'product_tree.product_groups.summary': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'want_to_have',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/product_tree/product_groups/product_group/summary-spec.en.md',
      usage: {
        generic:
          'docs/user/product_tree/product_groups/product_group/summary-usage.en.md',
      },
    },
  },
  'product_tree.relationships[]': {
    uiType: 'ARRAY',
    user_documentation: {
      specification:
        'docs/user/product_tree/relationships/relationship-spec.en.md',
      usage: {
        generic:
          'docs/user/product_tree/relationships/relationship-usage.en.md',
      },
    },
  },
  'product_tree.relationships': {
    propertyOrder: [
      'category',
      'full_product_name',
      'product_reference',
      'relates_to_product_reference',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'optional',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/product_tree/relationships-spec.en.md',
      usage: {
        generic: 'docs/user/product_tree/relationships-usage.en.md',
      },
    },
  },
  'product_tree.relationships.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/product_tree/relationships/relationship/category-spec.en.md',
      usage: {
        generic:
          'docs/user/product_tree/relationships/relationship/category-usage.en.md',
      },
    },
  },
  'product_tree.relationships.full_product_name': {
    propertyOrder: ['name', 'product_id', 'product_identification_helper'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/product_tree/relationships/relationship/full_product_name-spec.en.md',
      usage: {
        generic:
          'docs/user/product_tree/relationships/relationship/full_product_name-usage.en.md',
      },
    },
  },
  'product_tree.relationships.full_product_name.name': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/full_product_name/name-spec.en.md',
      usage: {
        generic: 'docs/user/types/full_product_name/name-usage.en.md',
      },
    },
  },
  'product_tree.relationships.full_product_name.product_id': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/full_product_name/product_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/full_product_name/product_id-usage.en.md',
      },
    },
  },
  'product_tree.relationships.full_product_name.product_identification_helper':
    {
      propertyOrder: [
        'cpe',
        'hashes',
        'model_numbers',
        'purl',
        'sbom_urls',
        'serial_numbers',
        'skus',
        'x_generic_uris',
      ],
      uiType: 'OBJECT',
      relevance_levels: {
        csaf_base: 'want_to_have',
        csaf_security_incident_response: 'want_to_have',
        csaf_informational_advisory: 'want_to_have',
        csaf_security_advisory: 'want_to_have',
        csaf_vex: 'want_to_have',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.cpe':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/cpe-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/cpe-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.hashes[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.hashes':
    {
      propertyOrder: ['file_hashes', 'filename'],
      uiType: 'OBJECT',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.hashes.file_hashes[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.hashes.file_hashes':
    {
      propertyOrder: ['algorithm', 'value'],
      uiType: 'OBJECT',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.hashes.file_hashes.algorithm':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/algorithm-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/algorithm-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.hashes.file_hashes.value':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/value-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/file_hashes/file_hash/value-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.hashes.filename':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/hashes/hash/filename-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/hashes/hash/filename-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.model_numbers[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/model_numbers/model_number-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/model_numbers/model_number-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.model_numbers':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/model_numbers-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/model_numbers-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.purl':
    {
      uiType: 'URI',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/purl-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/purl-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.sbom_urls[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/sbom_urls/sbom_url-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/sbom_urls/sbom_url-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.sbom_urls':
    {
      uiType: 'URI',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/sbom_urls-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/sbom_urls-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.serial_numbers[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/serial_numbers/serial_number-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/serial_numbers/serial_number-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.serial_numbers':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/serial_numbers-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/serial_numbers-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.skus[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/skus/sku-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/skus/sku-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.skus':
    {
      uiType: 'STRING',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'nice_to_know',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/skus-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/skus-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.x_generic_uris[]':
    {
      uiType: 'ARRAY',
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.x_generic_uris':
    {
      propertyOrder: ['namespace', 'uri'],
      uiType: 'OBJECT',
      relevance_levels: {
        csaf_base: 'nice_to_know',
        csaf_security_incident_response: 'nice_to_know',
        csaf_informational_advisory: 'nice_to_know',
        csaf_security_advisory: 'nice_to_know',
        csaf_vex: 'want_to_have',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.x_generic_uris.namespace':
    {
      uiType: 'URI',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/namespace-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/namespace-usage.en.md',
        },
      },
    },
  'product_tree.relationships.full_product_name.product_identification_helper.x_generic_uris.uri':
    {
      uiType: 'URI',
      relevance_levels: {
        csaf_base: 'mandatory',
        csaf_security_incident_response: 'mandatory',
        csaf_informational_advisory: 'mandatory',
        csaf_security_advisory: 'mandatory',
        csaf_vex: 'mandatory',
      },
      user_documentation: {
        specification:
          'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/uri-spec.en.md',
        usage: {
          generic:
            'docs/user/types/full_product_name/product_identification_helper/x_generic_uris/x_generic_uri/uri-usage.en.md',
        },
      },
    },
  'product_tree.relationships.product_reference': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/product_tree/relationships/relationship/product_reference-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
        specific:
          'docs/user/product_tree/relationships/relationship/product_reference-usage.en.md',
      },
    },
  },
  'product_tree.relationships.relates_to_product_reference': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/product_tree/relationships/relationship/relates_to_product_reference-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
        specific:
          'docs/user/product_tree/relationships/relationship/relates_to_product_reference-usage.en.md',
      },
    },
  },
  'vulnerabilities[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/vulnerabilities/vulnerability-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability-usage.en.md',
      },
    },
  },
  vulnerabilities: {
    propertyOrder: [
      'acknowledgments',
      'cve',
      'cwe',
      'discovery_date',
      'flags',
      'ids',
      'involvements',
      'notes',
      'product_status',
      'references',
      'release_date',
      'remediations',
      'scores',
      'threats',
      'title',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/vulnerabilities-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities-usage.en.md',
      },
    },
  },
  'vulnerabilities.acknowledgments[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment-spec.en.md',
      usage: {
        generic: 'docs/user/types/acknowledgments/acknowledgment-usage.en.md',
      },
    },
  },
  'vulnerabilities.acknowledgments': {
    propertyOrder: ['names', 'organization', 'summary', 'urls'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/acknowledgments-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/acknowledgments-usage.en.md',
      },
    },
  },
  'vulnerabilities.acknowledgments.names[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/names/name-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/names/name-usage.en.md',
      },
    },
  },
  'vulnerabilities.acknowledgments.names': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/names-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/names-usage.en.md',
      },
    },
  },
  'vulnerabilities.acknowledgments.organization': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/organization-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/organization-usage.en.md',
      },
    },
  },
  'vulnerabilities.acknowledgments.summary': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/summary-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/summary-usage.en.md',
      },
    },
  },
  'vulnerabilities.acknowledgments.urls[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/urls/url-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/urls/url-usage.en.md',
      },
    },
  },
  'vulnerabilities.acknowledgments.urls': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/types/acknowledgments/acknowledgment/urls-spec.en.md',
      usage: {
        generic:
          'docs/user/types/acknowledgments/acknowledgment/urls-usage.en.md',
      },
    },
  },
  'vulnerabilities.cve': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
    },
    user_documentation: {
      specification: 'docs/user/vulnerabilities/vulnerability/cve-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/cve-usage.en.md',
      },
    },
  },
  'vulnerabilities.cwe': {
    propertyOrder: ['id', 'name'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/vulnerabilities/vulnerability/cwe-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/cwe-usage.en.md',
      },
    },
  },
  'vulnerabilities.cwe.id': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/cwe/id-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/cwe/id-usage.en.md',
      },
    },
  },
  'vulnerabilities.cwe.name': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/cwe/name-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/cwe/name-usage.en.md',
      },
    },
  },
  'vulnerabilities.discovery_date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/discovery_date-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/discovery_date-usage.en.md',
      },
    },
  },
  'vulnerabilities.flags[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/flags/flag-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/flags/flag-usage.en.md',
      },
    },
  },
  'vulnerabilities.flags': {
    propertyOrder: ['date', 'group_ids', 'label', 'product_ids'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
    },
    user_documentation: {
      specification: 'docs/user/vulnerabilities/vulnerability/flags-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/flags-usage.en.md',
      },
    },
  },
  'vulnerabilities.flags.date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/flags/flag/date-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/flags/flag/date-usage.en.md',
      },
    },
  },
  'vulnerabilities.flags.group_ids[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/product_group_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_group_id-spec.en.md',
      },
    },
  },
  'vulnerabilities.flags.group_ids': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/flags/flag/group_ids-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/flags/flag/group_ids-usage.en.md',
      },
    },
  },
  'vulnerabilities.flags.label': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/flags/flag/label-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/flags/flag/label-usage.en.md',
      },
    },
  },
  'vulnerabilities.flags.product_ids[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/product_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
      },
    },
  },
  'vulnerabilities.flags.product_ids': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/flags/flag/product_ids-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/flags/flag/product_ids-usage.en.md',
      },
    },
  },
  'vulnerabilities.ids[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/ids/id-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/ids/id-usage.en.md',
      },
    },
  },
  'vulnerabilities.ids': {
    propertyOrder: ['system_name', 'text'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/vulnerabilities/vulnerability/ids-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/ids-usage.en.md',
      },
    },
  },
  'vulnerabilities.ids.system_name': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/ids/id/system_name-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/ids/id/system_name-usage.en.md',
      },
    },
  },
  'vulnerabilities.ids.text': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/ids/id/text-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/ids/id/text-usage.en.md',
      },
    },
  },
  'vulnerabilities.involvements[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/involvements/involvement-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/involvements/involvement-usage.en.md',
      },
    },
  },
  'vulnerabilities.involvements': {
    propertyOrder: ['date', 'party', 'status', 'summary'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/involvements-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/involvements-usage.en.md',
      },
    },
  },
  'vulnerabilities.involvements.date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/involvements/involvement/date-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/involvements/involvement/date-usage.en.md',
      },
    },
  },
  'vulnerabilities.involvements.party': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/involvements/involvement/party-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/involvements/involvement/party-usage.en.md',
      },
    },
  },
  'vulnerabilities.involvements.status': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/involvements/involvement/status-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/involvements/involvement/status-usage.en.md',
      },
    },
  },
  'vulnerabilities.involvements.summary': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/involvements/involvement/summary-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/involvements/involvement/summary-usage.en.md',
      },
    },
  },
  'vulnerabilities.notes[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note-usage.en.md',
      },
    },
  },
  'vulnerabilities.notes': {
    propertyOrder: ['audience', 'category', 'text', 'title'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/vulnerabilities/vulnerability/notes-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/notes-usage.en.md',
      },
    },
  },
  'vulnerabilities.notes.audience': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note/audience-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note/audience-usage.en.md',
      },
    },
  },
  'vulnerabilities.notes.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note/category-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note/category-usage.en.md',
      },
    },
  },
  'vulnerabilities.notes.text': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note/text-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note/text-usage.en.md',
      },
    },
  },
  'vulnerabilities.notes.title': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification: 'docs/user/types/notes/note/title-spec.en.md',
      usage: {
        generic: 'docs/user/types/notes/note/title-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status': {
    propertyOrder: [
      'first_affected',
      'first_fixed',
      'fixed',
      'known_affected',
      'known_not_affected',
      'last_affected',
      'recommended',
      'under_investigation',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.first_affected[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/products-spec.en.md',
      usage: {
        generic: 'docs/user/types/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.first_affected': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status/first_affected-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status/first_affected-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.first_fixed[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/products-spec.en.md',
      usage: {
        generic: 'docs/user/types/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.first_fixed': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status/first_fixed-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status/first_fixed-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.fixed[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/products-spec.en.md',
      usage: {
        generic: 'docs/user/types/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.fixed': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status/fixed-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status/fixed-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.known_affected[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/products-spec.en.md',
      usage: {
        generic: 'docs/user/types/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.known_affected': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status/known_affected-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status/known_affected-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.known_not_affected[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/products-spec.en.md',
      usage: {
        generic: 'docs/user/types/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.known_not_affected': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status/known_not_affected-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status/known_not_affected-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.last_affected[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/products-spec.en.md',
      usage: {
        generic: 'docs/user/types/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.last_affected': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status/last_affected-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status/last_affected-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.recommended[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/products-spec.en.md',
      usage: {
        generic: 'docs/user/types/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.recommended': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status/recommended-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status/recommended-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.under_investigation[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/products-spec.en.md',
      usage: {
        generic: 'docs/user/types/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.product_status.under_investigation': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/product_status/under_investigation-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/product_status/under_investigation-usage.en.md',
      },
    },
  },
  'vulnerabilities.references[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/references/reference-spec.en.md',
      usage: {
        generic: 'docs/user/types/references/reference-usage.en.md',
      },
    },
  },
  'vulnerabilities.references': {
    propertyOrder: ['category', 'summary', 'url'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/references-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/references-usage.en.md',
      },
    },
  },
  'vulnerabilities.references.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/types/references/reference/category-spec.en.md',
      usage: {
        generic: 'docs/user/types/references/reference/category-usage.en.md',
      },
    },
  },
  'vulnerabilities.references.summary': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/references/reference/summary-spec.en.md',
      usage: {
        generic: 'docs/user/types/references/reference/summary-usage.en.md',
      },
    },
  },
  'vulnerabilities.references.url': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification: 'docs/user/types/references/reference/url-spec.en.md',
      usage: {
        generic: 'docs/user/types/references/reference/url-usage.en.md',
      },
    },
  },
  'vulnerabilities.release_date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/release_date-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/release_date-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations': {
    propertyOrder: [
      'category',
      'date',
      'details',
      'entitlements',
      'group_ids',
      'product_ids',
      'restart_required',
      'url',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/category-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/category-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/date-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/date-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.details': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/details-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/details-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.entitlements[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/entitlements/entitlement-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/entitlements/entitlement-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.entitlements': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/entitlements-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/entitlements-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.group_ids[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/product_group_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_group_id-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.group_ids': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/group_ids-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/group_ids-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.product_ids[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/product_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.product_ids': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/product_ids-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/product_ids-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.restart_required': {
    propertyOrder: ['category', 'details'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/restart_required-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/restart_required-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.restart_required.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/restart_required/category-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/restart_required/category-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.restart_required.details': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/restart_required/details-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/restart_required/details-usage.en.md',
      },
    },
  },
  'vulnerabilities.remediations.url': {
    uiType: 'URI',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/remediations/remediation/url-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/remediations/remediation/url-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores': {
    propertyOrder: ['cvss_v2', 'cvss_v3', 'products'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/scores-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2': {
    propertyOrder: [
      'version',
      'vectorString',
      'accessVector',
      'accessComplexity',
      'authentication',
      'confidentialityImpact',
      'integrityImpact',
      'availabilityImpact',
      'exploitability',
      'remediationLevel',
      'reportConfidence',
      'collateralDamagePotential',
      'targetDistribution',
      'confidentialityRequirement',
      'integrityRequirement',
      'availabilityRequirement',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.version': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.vectorString': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.accessVector': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.accessComplexity': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.authentication': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.confidentialityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.integrityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.availabilityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.exploitability': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.remediationLevel': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.reportConfidence': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.collateralDamagePotential': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.targetDistribution': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.confidentialityRequirement': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.integrityRequirement': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v2.availabilityRequirement': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v2-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3': {
    propertyOrder: [
      'version',
      'vectorString',
      'attackVector',
      'attackComplexity',
      'privilegesRequired',
      'userInteraction',
      'scope',
      'confidentialityImpact',
      'integrityImpact',
      'availabilityImpact',
      'baseSeverity',
      'exploitCodeMaturity',
      'remediationLevel',
      'reportConfidence',
      'temporalSeverity',
      'confidentialityRequirement',
      'integrityRequirement',
      'availabilityRequirement',
      'modifiedAttackVector',
      'modifiedAttackComplexity',
      'modifiedPrivilegesRequired',
      'modifiedUserInteraction',
      'modifiedScope',
      'modifiedConfidentialityImpact',
      'modifiedIntegrityImpact',
      'modifiedAvailabilityImpact',
      'environmentalSeverity',
    ],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.version': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.vectorString': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.attackVector': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.attackComplexity': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.privilegesRequired': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.userInteraction': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.scope': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.confidentialityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.integrityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.availabilityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'best_practice',
      csaf_security_incident_response: 'best_practice',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.baseSeverity': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.exploitCodeMaturity': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
      csaf_vex: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.remediationLevel': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.reportConfidence': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.temporalSeverity': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'want_to_have',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.confidentialityRequirement': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.integrityRequirement': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.availabilityRequirement': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.modifiedAttackVector': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.modifiedAttackComplexity': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.modifiedPrivilegesRequired': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.modifiedUserInteraction': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.modifiedScope': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.modifiedConfidentialityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.modifiedIntegrityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.modifiedAvailabilityImpact': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.cvss_v3.environmentalSeverity': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'optional',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'optional',
      csaf_vex: 'optional',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/cvss_v3-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.products[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/product_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
      },
    },
  },
  'vulnerabilities.scores.products': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/scores/score/products-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/scores/score/products-usage.en.md',
      },
    },
  },
  'vulnerabilities.threats[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/threats/threat-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/threats/threat-usage.en.md',
      },
    },
  },
  'vulnerabilities.threats': {
    propertyOrder: ['category', 'date', 'details', 'group_ids', 'product_ids'],
    uiType: 'OBJECT',
    relevance_levels: {
      csaf_base: 'optional',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'nice_to_know',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/threats-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/threats-usage.en.md',
      },
    },
  },
  'vulnerabilities.threats.category': {
    uiType: 'ENUM',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/threats/threat/category-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/threats/threat/category-usage.en.md',
      },
    },
  },
  'vulnerabilities.threats.date': {
    uiType: 'DATETIME',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/threats/threat/date-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/threats/threat/date-usage.en.md',
      },
    },
  },
  'vulnerabilities.threats.details': {
    uiType: 'MULTI_LINE',
    relevance_levels: {
      csaf_base: 'mandatory',
      csaf_security_incident_response: 'mandatory',
      csaf_informational_advisory: 'mandatory',
      csaf_security_advisory: 'mandatory',
      csaf_vex: 'mandatory',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/threats/threat/details-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/threats/threat/details-usage.en.md',
      },
    },
  },
  'vulnerabilities.threats.group_ids[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/product_group_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_group_id-spec.en.md',
      },
    },
  },
  'vulnerabilities.threats.group_ids': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'nice_to_know',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/threats/threat/group_ids-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/threats/threat/group_ids-usage.en.md',
      },
    },
  },
  'vulnerabilities.threats.product_ids[]': {
    uiType: 'ARRAY',
    relevance_levels: {
      csaf_informational_advisory: 'excluded',
    },
    user_documentation: {
      specification: 'docs/user/types/product_id-spec.en.md',
      usage: {
        generic: 'docs/user/types/product_id-usage.en.md',
      },
    },
  },
  'vulnerabilities.threats.product_ids': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'want_to_have',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
    },
    user_documentation: {
      specification:
        'docs/user/vulnerabilities/vulnerability/threats/threat/product_ids-spec.en.md',
      usage: {
        generic:
          'docs/user/vulnerabilities/vulnerability/threats/threat/product_ids-usage.en.md',
      },
    },
  },
  'vulnerabilities.title': {
    uiType: 'STRING',
    relevance_levels: {
      csaf_base: 'nice_to_know',
      csaf_security_incident_response: 'want_to_have',
      csaf_informational_advisory: 'excluded',
      csaf_security_advisory: 'best_practice',
      csaf_vex: 'want_to_have',
    },
    user_documentation: {
      specification: 'docs/user/vulnerabilities/vulnerability/title-spec.en.md',
      usage: {
        generic: 'docs/user/vulnerabilities/vulnerability/title-usage.en.md',
      },
    },
  },
}

import prettier from 'prettier'
import * as additional_props from './config/additionalProperties.json'
import * as meta_data2 from './config/metaData2.json'
import * as csaf_json_schema from './schema_files/csaf_json_schema.json'
import * as cvss_v2_0_json from './schema_files/cvss-v2.0.json'
import * as cvss_v3_0_json from './schema_files/cvss-v3.0.json'
import * as cvss_v3_1_json from './schema_files/cvss-v3.1.json'

import fs from 'fs'

const MetaDataType = /** @type {const} */ ({
  // eslint-disable-next-line no-unused-vars
  STRING: 'STRING',
  // eslint-disable-next-line no-unused-vars
  URI: 'URI',
  // eslint-disable-next-line no-unused-vars
  DATETIME: 'DATETIME',
  // eslint-disable-next-line no-unused-vars
  OBJECT: 'OBJECT',
  // eslint-disable-next-line no-unused-vars
  ARRAY: 'ARRAY',

  RECURSION: 'RECURSION',
})

export const UiTypeEnum = /** @type {const} */ ({
  ENUM: 'ENUM',
  MULTI_LINE: 'MULTI_LINE',
})

/**
 * @param {string} key
 * @param {string[]} parentFullName
 * @param {import('./metainfo/types').SchemaProperty} propertyToConvert
 * @param {boolean} mandatory
 * @param {import('./metainfo/types').SchemaProperty} root
 * @param {Map<string, string[]>} parentRefs
 * @returns {null | import('./metainfo/types').MetaProperty}
 */
function convertRef(
  key,
  parentFullName,
  propertyToConvert,
  mandatory,
  root,
  parentRefs
) {
  const refName = /** @type {any} */ (propertyToConvert)['$ref']
  /** @type {import('./metainfo/types').MetaProperty | null} */
  let refType = null

  if (refName.startsWith('https://')) {
    /** @type {import('./metainfo/types').SchemaProperty} */
    let refJson = { title: 'unknown', properties: {} }
    if (refName === 'https://www.first.org/cvss/cvss-v2.0.json') {
      refJson = /** @type {any} */ (cvss_v2_0_json)
    } else if (refName === 'https://www.first.org/cvss/cvss-v3.0.json') {
      refJson = /** @type {any} */ (cvss_v3_0_json)
    } else if (refName === 'https://www.first.org/cvss/cvss-v3.1.json') {
      refJson = /** @type {any} */ (cvss_v3_1_json)
    }
    refType = convertSchemaPropToMeta(
      key,
      parentFullName,
      refJson,
      false,
      refJson,
      parentRefs
    )
  } else if (parentRefs.has(refName)) {
    // recursion
    /** @type {import('./metainfo/types').MetaInfoReference} */
    const metaInfo = {
      refType: parentRefs.get(refName),
    }

    refType = {
      key,
      fullName: parentFullName.concat(key),
      title: propertyToConvert.title,
      type: MetaDataType.RECURSION,
      description: propertyToConvert.description,
      mandatory,
      metaInfo,
    }
  } else {
    /** @type {string[]} */
    const refPath = refName.split('/')
    let refNode = root
    // refPath starts with # for example: #/$defs/product_id_t
    // eslint-disable-next-line no-plusplus
    for (let i = 1; i < refPath.length; i++) {
      refNode = /** @type {any} */ (refNode)[refPath[i]]
    }

    const refCopy = new Map(parentRefs)
    refCopy.set(refName, parentFullName.concat(key))
    refType = convertSchemaPropToMeta(
      key,
      parentFullName,
      refNode,
      mandatory,
      root,
      refCopy
    )
    if (refType) {
      refType.refTitle = propertyToConvert.title
      refType.refDescription = propertyToConvert.description
    }
  }
  return refType
}

/**
 * @param {string} key
 * @param {string[]} parentFullName
 * @param {import('./metainfo/types').SchemaProperty} propertyToConvert
 * @param {boolean} mandatory
 * @param {import('./metainfo/types').SchemaProperty} root
 * @param {Map<string, string[]>} parentRefs
 * @returns {null | import('./metainfo/types').MetaProperty}
 */
function convertObject(
  key,
  parentFullName,
  propertyToConvert,
  mandatory,
  root,
  parentRefs
) {
  /** @type {string[]} */
  const requiredProperties = propertyToConvert.required
    ? propertyToConvert.required
    : []
  const objectProperties = propertyToConvert.properties
    ? propertyToConvert.properties
    : []

  /** @type {import('./metainfo/types').MetaInfoObject} */
  const metaInfo = {
    propertyList: [],
    minProperties: propertyToConvert.minProperties,
    maxProperties: propertyToConvert.maxProperties,
  }
  metaInfo.propertyList = []

  const newFullName = key ? parentFullName.concat(key) : parentFullName
  /** @type {import('./metainfo/types').MetaProperty} */
  const result = {
    key,
    fullName: newFullName,
    title: propertyToConvert.title,
    type: MetaDataType.OBJECT,
    description: propertyToConvert.description,
    mandatory,
    metaInfo,
  }

  // eslint-disable-next-line guard-for-in,no-restricted-syntax
  for (const propName in objectProperties) {
    /** @type {import('./metainfo/types').MetaProperty | null} */
    const subProperty = convertSchemaPropToMeta(
      propName,
      result.fullName,
      /** @type {any} */ (objectProperties)[propName],
      requiredProperties.includes(propName),
      root,
      parentRefs
    )
    if (subProperty) {
      metaInfo.propertyList.push(subProperty)
    }
  }
  return result
}

/**
 * @param {string} key
 * @param {string[]} parentFullName
 * @param {import('./metainfo/types').SchemaProperty} propertyToConvert
 * @param {boolean} mandatory
 * @returns {null | import('./metainfo/types').MetaProperty}
 */
function convertString(key, parentFullName, propertyToConvert, mandatory) {
  /** @type {import('./metainfo/types').MetaDataType} */
  let type = MetaDataType.STRING
  if (propertyToConvert.format === 'uri') {
    type = MetaDataType.URI
  } else if (propertyToConvert.format === 'date-time') {
    type = MetaDataType.DATETIME
  }

  /** @type {import('./metainfo/types').MetaInfoString} */
  const metaInfo = {
    minLength: propertyToConvert.minLength,
    examples: propertyToConvert.examples,
    enumValues: propertyToConvert.enum,
    pattern: propertyToConvert.pattern,
    default: propertyToConvert.default,
  }

  /** @type {import('./metainfo/types').MetaProperty} */
  const result = {
    key,
    fullName: parentFullName.concat(key),
    type,
    title: propertyToConvert.title,
    description: propertyToConvert.description,
    mandatory,
    metaInfo,
  }
  return result
}

/**
 * @param {string} key
 * @param {string[]} parentFullName
 * @param {import('./metainfo/types').SchemaProperty} propertyToConvert
 * @param {boolean} mandatory
 * @param {import('./metainfo/types').SchemaProperty} root
 * @param {Map<string, string[]>} parentRefs
 * @returns {null | import('./metainfo/types').MetaProperty}
 */
function convertArray(
  key,
  parentFullName,
  propertyToConvert,
  mandatory,
  root,
  parentRefs
) {
  /** @type {import('./metainfo/types').MetaProperty | null} */
  let arrayType = null
  if (propertyToConvert.items) {
    arrayType = convertSchemaPropToMeta(
      '',
      parentFullName.concat(key),
      propertyToConvert.items,
      false,
      root,
      parentRefs
    )
    if (arrayType) {
      arrayType.fullName = parentFullName.concat(key)
    }
  }

  /** @type {import('./metainfo/types').MetaInfoArray} */
  const metaInfo = {
    minItem: propertyToConvert.minItems,
    uniqueItems: propertyToConvert.uniqueItems,
    arrayType,
  }

  /** @type {import('./metainfo/types').MetaProperty} */
  const result = {
    key,
    fullName: parentFullName.concat(key),
    title: propertyToConvert.title,
    type: MetaDataType.ARRAY,
    description: propertyToConvert.description,
    mandatory,
    metaInfo,
  }
  return result
}

/**
 * @param {string} key
 * @param {string[]} parentFullName
 * @param {import('./metainfo/types').SchemaProperty} propertyToConvert
 * @param {boolean} mandatory
 * @param {import('./metainfo/types').SchemaProperty} root
 * @param {Map<string, string[]>} parentRefs
 * @returns {null | import('./metainfo/types').MetaProperty}
 */
export function convertSchemaPropToMeta(
  key,
  parentFullName,
  propertyToConvert,
  mandatory,
  root,
  parentRefs
) {
  if (/** @type {any} */ (propertyToConvert)['$ref']) {
    return convertRef(
      key,
      parentFullName,
      propertyToConvert,
      mandatory,
      root,
      parentRefs
    )
  }
  if (propertyToConvert.type === 'object') {
    return convertObject(
      key,
      parentFullName,
      propertyToConvert,
      mandatory,
      root,
      parentRefs
    )
  }
  if (propertyToConvert.type === 'string') {
    return convertString(key, parentFullName, propertyToConvert, mandatory)
  }
  if (propertyToConvert.type === 'array') {
    return convertArray(
      key,
      parentFullName,
      propertyToConvert,
      mandatory,
      root,
      parentRefs
    )
  }
  if (propertyToConvert.oneOf) {
    const lastProperty =
      propertyToConvert.oneOf[propertyToConvert.oneOf.length - 1]
    return convertSchemaPropToMeta(
      key,
      parentFullName,
      lastProperty,
      mandatory,
      root,
      parentRefs
    )
  }
  return null
}

/**
 * Iterate recursive over the schema property tree and call the handler for every node
 * @param {import('./metainfo/types').MetaProperty} root start node
 * @param {import('./metainfo/types').MetaPropertyHandler} handler handler
 */
function iterateOverProperties(root, handler) {
  handler(root)
  if (root.type === MetaDataType.ARRAY) {
    //iterate over the array type
    root.fullName
    const array = /** @type {import('./metainfo/types').MetaInfoArray} */ (
      root.metaInfo
    )
    iterateOverProperties(
      /** @type {import('./metainfo/types').MetaProperty} */ (array.arrayType),
      handler
    )
  } else if (root.type === MetaDataType.OBJECT) {
    //iterate all properties of the object
    const object = /** @type {import('./metainfo/types').MetaInfoObject} */ (
      root.metaInfo
    )
    object.propertyList.forEach((property) =>
      iterateOverProperties(property, handler)
    )
  }
}

/**
 * Create the default additional properties for every object node on the property tree.
 * Create a propertyOrder for every object in the tree with all sub properties of the object
 * @param {import('./metainfo/types').MetaProperty} rootProperty root of the property tree
 * @param {any} metaInfo2Data the metaData2.json
 */
export function createDefaultAdditionalProperties(rootProperty, metaInfo2Data) {
  /** @type {any} */
  const additionalProperties = {}

  /**
   * @param {import('./metainfo/types').MetaProperty} property
   * @param {boolean} [string_is_multiline]
   * @returns
   */
  function detectUiType(property, string_is_multiline) {
    /** @type {import('./metainfo/types').UiType} */
    let uiType = property.type
    if (property.type === MetaDataType.STRING) {
      const metaInfo =
        /** @type {import('./metainfo/types').MetaInfoString} */ (
          property.metaInfo
        )
      if (metaInfo.enumValues && metaInfo.enumValues.length > 0) {
        uiType = UiTypeEnum.ENUM
      } else if (string_is_multiline) {
        uiType = UiTypeEnum.MULTI_LINE
      }
    }
    return uiType
  }

  /**
   * @param {import('./metainfo/types').MetaProperty} property
   */
  function createPropertiesHandler(property) {
    if (property.type === MetaDataType.OBJECT) {
      const object = /** @type {import('./metainfo/types').MetaInfoObject} */ (
        property.metaInfo
      )
      const properties = object.propertyList.map((metaProp) => metaProp.key)
      const fullPropName = property.fullName.join('.')
      const metaInfo2Prop = metaInfo2Data[fullPropName]
      /** @type {any} */
      const newProperty = { propertyOrder: properties, uiType: property.type }
      if (metaInfo2Prop && metaInfo2Prop['relevance_levels']) {
        newProperty['relevance_levels'] = metaInfo2Prop['relevance_levels']
      }
      if (metaInfo2Prop && metaInfo2Prop['user_documentation']) {
        newProperty['user_documentation'] = metaInfo2Prop['user_documentation']
      }
      additionalProperties[fullPropName] = newProperty
    } else if (property.type === MetaDataType.ARRAY) {
      const fullPropName = property.fullName.join('.') + '[]'
      const metaInfo2Prop = metaInfo2Data[fullPropName]
      /** @type {any} */
      const newProperty = { uiType: property.type }
      if (metaInfo2Prop && metaInfo2Prop['relevance_levels']) {
        newProperty['relevance_levels'] = metaInfo2Prop['relevance_levels']
      }
      if (metaInfo2Prop && metaInfo2Prop['user_documentation']) {
        newProperty['user_documentation'] = metaInfo2Prop['user_documentation']
      }
      additionalProperties[fullPropName] = newProperty
    } else if (
      property.type === MetaDataType.STRING ||
      property.type === MetaDataType.URI ||
      property.type === MetaDataType.DATETIME
    ) {
      const fullPropName = property.fullName.join('.')
      const metaInfo2Prop = metaInfo2Data[fullPropName]
      const stringIsMultiline = metaInfo2Prop
        ? metaInfo2Prop['string_is_multiline']
        : false
      /** @type {any} */
      const newProperty = { uiType: detectUiType(property, stringIsMultiline) }
      if (metaInfo2Prop && metaInfo2Prop['relevance_levels']) {
        newProperty['relevance_levels'] = metaInfo2Prop['relevance_levels']
      }
      if (metaInfo2Prop && metaInfo2Prop['user_documentation']) {
        newProperty['user_documentation'] = metaInfo2Prop['user_documentation']
      }
      additionalProperties[fullPropName] = newProperty
    }
  }

  iterateOverProperties(rootProperty, createPropertiesHandler)
  return additionalProperties
}

/**
 * @param {import('./metainfo/types').MetaInfoObject} objectMetaInfo
 * @param {string[]} propertyOrder
 */
export function sortPropertiesBy(objectMetaInfo, propertyOrder) {
  if (propertyOrder) {
    const properties = objectMetaInfo.propertyList
    /** @type {import('./metainfo/types').MetaProperty[]} */
    const sortedProperties = []

    // move properties into sortedProperties by propertyOrder
    propertyOrder.forEach((propertyName) => {
      const index = properties.findIndex(
        (metaProp) => metaProp.key === propertyName
      )
      if (index >= 0) {
        sortedProperties.push(properties.splice(index, 1)[0])
      }
    })
    sortedProperties.push(...properties)
    objectMetaInfo.propertyList = sortedProperties
  }
}

/**
 * Extends every object in the tree with the properties defined on the additional_props JSON
 * @param {import('./metainfo/types').MetaProperty} rootProperty root node of the property tree
 * @param {any} propsToAdd additional properties to add
 */
export function extendWithAdditionalInfo(rootProperty, propsToAdd) {
  /**
   * @param {any} property
   */
  function extendPropertiesHandler(property) {
    if (property.type === MetaDataType.OBJECT) {
      const object = /** @type {import('./metainfo/types').MetaInfoObject} */ (
        property.metaInfo
      )
      const fullPropName = property.fullName.join('.')
      const add_prop = propsToAdd[fullPropName]
      if (add_prop) {
        sortPropertiesBy(object, add_prop['propertyOrder'])
        if (add_prop['addMenuItemsForChildObjects']) {
          /** @type {any} */ property['addMenuItemsForChildObjects'] =
            add_prop['addMenuItemsForChildObjects']
        }
        if (add_prop['relevance_levels']) {
          /** @type {any} */ property['relevance_levels'] =
            add_prop['relevance_levels']
        }
        if (add_prop['user_documentation']) {
          /** @type {any} */ property['user_documentation'] =
            add_prop['user_documentation']
        }
        /** @type {any} */ property['uiType'] =
          add_prop && add_prop['uiType'] ? add_prop['uiType'] : property.type
      }
    } else if (property.type === MetaDataType.ARRAY) {
      const fullPropName = property.fullName.join('.') + '[]'
      const add_prop = propsToAdd[fullPropName]
      if (add_prop && add_prop['relevance_levels']) {
        /** @type {any} */ property['relevance_levels'] =
          add_prop['relevance_levels']
      }
      if (add_prop && add_prop['user_documentation']) {
        /** @type {any} */ property['user_documentation'] =
          add_prop['user_documentation']
      }
      /** @type {any} */ property['uiType'] =
        add_prop && add_prop['uiType'] ? add_prop['uiType'] : property.type
    } else if (
      property.type === MetaDataType.STRING ||
      property.type === MetaDataType.DATETIME ||
      property.type === MetaDataType.URI
    ) {
      const fullPropName = property.fullName.join('.')
      const add_prop = propsToAdd[fullPropName]
      if (add_prop) {
        if (add_prop['relevance_levels']) {
          /** @type {any} */ property['relevance_levels'] =
            add_prop['relevance_levels']
        }
        if (add_prop['user_documentation']) {
          /** @type {any} */ property['user_documentation'] =
            add_prop['user_documentation']
        }
      }
      /** @type {any} */ property['uiType'] =
        add_prop && add_prop['uiType'] ? add_prop['uiType'] : property.type
    }
  }

  iterateOverProperties(rootProperty, extendPropertiesHandler)
}

/**
 * Extends every object in the tree with the properties 'relevance_levels' and 'string_is_multiline' defined in the propsToAdd JSON
 * @param {import('./metainfo/types').MetaProperty} rootProperty root node of the property tree
 * @param {any} propsToAdd  property to merge in tne tree
 */
export function extendWithMetaInfo2(rootProperty, propsToAdd) {
  /**
   * @param {any} property
   */
  function extendPropertiesHandler(property) {
    if (
      property.type === MetaDataType.OBJECT ||
      property.type === MetaDataType.STRING ||
      property.type === MetaDataType.DATETIME
    ) {
      const fullPropName = property.fullName.join('.')
      const add_prop = propsToAdd[fullPropName]
      if (add_prop) {
        if (add_prop['relevance_levels']) {
          property['relevance_levels'] = add_prop['relevance_levels']
        }
        if (add_prop['string_is_multiline']) {
          property['string_is_multiline'] = add_prop['string_is_multiline']
        }
        if (add_prop['user_documentation']) {
          property['user_documentation'] = add_prop['user_documentation']
        }
      }
    } else if (property.type === MetaDataType.ARRAY) {
      const fullPropName = property.fullName.join('.') + '[]'
      const add_prop = propsToAdd[fullPropName]
      if (add_prop && add_prop['relevance_levels']) {
        property['relevance_levels'] = add_prop['relevance_levels']
      }
      if (add_prop && add_prop['user_documentation']) {
        property['user_documentation'] = add_prop['user_documentation']
      }
    }
  }

  iterateOverProperties(rootProperty, extendPropertiesHandler)
}

/**
 * write the metadata of the property tree as JSON file
 * @param {import('./metainfo/types').MetaProperty} rootProperty
 */
function writeMetadataJson(rootProperty) {
  const jsonMetainfo = JSON.stringify(rootProperty)
  fs.writeFile('./generated/metainfo.json', jsonMetainfo, 'utf8', (err) => {
    if (err) {
      console.log(`Error writing metadata json file: ${err}`)
    } else {
      console.log(`Metainfo File is written successfully!`)
    }
  })
}

/**
 * generate the list of the default additional properties as JSON file
 * @param {import('./metainfo/types').MetaProperty} rootProperty
 * @param {any} propsToAdd
 */
function writeDefaultAdditionalProperties(rootProperty, propsToAdd) {
  const additionalProperties = createDefaultAdditionalProperties(
    rootProperty,
    propsToAdd
  )
  const jsonOrderMapping = JSON.stringify(additionalProperties)
  fs.writeFile(
    './generated/additionalProperties.json',
    jsonOrderMapping,
    'utf8',
    (err) => {
      if (err) {
        console.log(`Error writing file: ${err}`)
      } else {
        console.log(`Additional Properties File is written successfully!`)
      }
    }
  )
}

/**
 * @param {import('./metainfo/types').MetaProperty} rootProperty
 */
function writeExtendedMetaInfoAsJavascript(rootProperty) {
  const extendedSchemaJson = JSON.stringify(rootProperty)
  const outputFile = './generated/schema.js'
  const prettierString = prettier.format(
    "/** @typedef {import('./shared/types').Property} Property */\n" +
      `export default (${extendedSchemaJson})`,
    {
      parser: 'typescript',
      singleQuote: true,
    }
  )
  fs.writeFile(outputFile, prettierString, 'utf8', (err) => {
    if (err) {
      console.log(`Error writing file: ${err}`)
    } else {
      console.log(`Schema Javascript File is written successfully!`)
    }
  })
}

export function convertCsafSchema() {
  // create property tree from schema
  const rootProperty = convertSchemaPropToMeta(
    '',
    [],
    /** @type {any} */ (csaf_json_schema),
    true,
    /** @type {any} */ (csaf_json_schema),
    new Map()
  )

  const fs = require('fs')
  if (!fs.existsSync('./generated')) {
    fs.mkdirSync('./generated')
  }

  // ONLY FOR INITIAL CREATION: create base additionalProperties.json file
  writeMetadataJson(/** @type {any} */ (rootProperty))
  writeDefaultAdditionalProperties(
    /** @type {any} */ (rootProperty),
    meta_data2
  )

  // extend property tree with information from additionalProperties.json
  extendWithAdditionalInfo(/** @type {any} */ (rootProperty), additional_props)
  writeExtendedMetaInfoAsJavascript(/** @type {any} */ (rootProperty))
}

convertCsafSchema()

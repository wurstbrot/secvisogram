// eslint-disable-next-line no-shadow
export type MetaDataType =
  | 'STRING'
  | 'URI'
  | 'DATETIME'
  | 'OBJECT'
  | 'ARRAY'
  | 'RECURSION'

export type UiTypeEnum = 'ENUM' | 'MULTI_LINE'

export type UiType = MetaDataType | UiTypeEnum

export interface MetaProperty {
  key: string
  fullName: string[]
  title?: string
  description?: string
  type: MetaDataType
  mandatory: boolean
  // eslint-disable-next-line no-use-before-define
  metaInfo?: MetaInfoArray | MetaInfoString | MetaInfoObject | MetaInfoReference
  refTitle?: string
  refDescription?: string
}

export interface MetaInfoObject {
  propertyList: MetaProperty[]
  minProperties?: number
  maxProperties?: number
}

export interface MetaInfoArray {
  minItem?: number
  arrayType: MetaProperty | null
  uniqueItems?: boolean
}

export interface MetaInfoString {
  minLength?: number
  examples?: string[]
  enumValues?: string[]
  pattern?: string
  default?: string
}

export interface MetaInfoReference {
  refType: string[] | undefined
}

export interface MetaPropertyHandler {
  (property: MetaProperty): void
}

export interface SchemaProperty {
  title: string
  description?: string
  type?: string
  required?: string[]
  minLength?: number
  examples?: string[]
  enum?: string[]
  pattern?: string
  default?: string
  properties: object
  minItems?: number
  uniqueItems?: boolean
  items?: SchemaProperty
  format?: string
  minProperties?: number
  maxProperties?: number
  oneOf?: SchemaProperty[]
}

import { getObjectMenuPaths } from '../../../lib/app/SecvisogramPage/View/WizardTab/editors/GenericEditor/ObjectEditor.js'
import schema from '../../../lib/app/SecvisogramPage/View/WizardTab/schema.js'
import { getLoginEnabledConfig } from '../../fixtures/appConfigData.js'

describe('SecvisogramPage / WizardTab', function () {
  it('can display usage help', function () {
    cy.intercept(
      '/.well-known/appspecific/de.bsi.secvisogram.json',
      getLoginEnabledConfig()
    ).as('wellKnownAppConfig')

    cy.visit('?tab=WIZZARD')
    cy.wait('@wellKnownAppConfig')

    cy.get(`[data-testid="document-acknowledgments-infoButton"]`).click()
    cy.get(`[data-testid="sideBar-DOCUMENTATION-button"]`).click()
    const infoPanelContent = cy.get('[data-testid="infoPanel-content"]')
    infoPanelContent.should('exist')
    infoPanelContent.should('contain.text', 'Acknowledgments - Usage')
  })

  describe('recursion fields work', function () {
    it('branches tree', function () {
      cy.intercept('/.well-known/appspecific/de.bsi.secvisogram.json', {
        statusCode: 404,
        body: {},
      }).as('wellKnownAppConfig')

      cy.visit('?tab=WIZZARD')
      cy.wait('@wellKnownAppConfig')

      cy.get(`[data-testid="menu_entry-/product_tree/branches"]`).click()
      cy.get(
        `[data-testid="menu_entry-/product_tree/branches-add_item_button"]`
      ).click()
      cy.get(
        `[data-testid="menu_entry-/product_tree/branches/0/branches-add_item_button"]`
      ).click()
    })
  })

  describe('getMenuPaths()', function () {
    it('can calculate the menu structure for the top level sidebar', function () {
      expect(
        getObjectMenuPaths(
          /** @type {import('../../../lib/app/SecvisogramPage/View/WizardTab/schema.js').Property} */ (
            schema
          )
        )
      ).to.deep.equal([
        { instancePath: ['document'] },
        { instancePath: ['document', 'acknowledgments'] },
        { instancePath: ['document', 'aggregate_severity'] },
        { instancePath: ['document', 'distribution'] },
        { instancePath: ['document', 'notes'] },
        { instancePath: ['document', 'publisher'] },
        { instancePath: ['document', 'references'] },
        { instancePath: ['document', 'tracking'] },
        { instancePath: ['product_tree'] },
        { instancePath: ['product_tree', 'branches'] },
        { instancePath: ['product_tree', 'full_product_names'] },
        { instancePath: ['product_tree', 'product_groups'] },
        { instancePath: ['product_tree', 'relationships'] },
        { instancePath: ['vulnerabilities'] },
      ])
    })
  })
})

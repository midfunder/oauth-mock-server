describe('login', () => {
    beforeEach(() => {
        cy.visit('https://webapp.dev.local')
    })

    it('login', () => {
        cy.get('#btn-login').should('contain', 'Log In')
        cy.get('#btn-login').click()
        cy.url().should('include', 'login')

        cy.get('input[name=email]').type('user@example.com')
        cy.get('input[name=name]').type('John Doe')
        cy.get('button').click()

        cy.get('.main span').should('contain', 'user@example.com')
    })
})
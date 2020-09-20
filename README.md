# Security

> config/components/security.yaml

<code>
security:<br>
    &nbsp;&nbsp;&nbsp;&nbsp;# Error messages to return<br>
    &nbsp;&nbsp;&nbsp;&nbsp;messages:<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;missing_parameter: "Merci de renseigner votre identifiant et votre mot de passe"<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;user_not_found: "Vous n'avez pas de compte enregistré"<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;invalid_password: "Mot de passe invalide"<br>
<br>
    &nbsp;&nbsp;&nbsp;&nbsp;redirect_to_route: login<br>
<br>
users:<br>
    &nbsp;&nbsp;&nbsp;&nbsp;App\Entity\User:<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;algorithm: default<br>
<br>
roles:<br>
    &nbsp;&nbsp;&nbsp;&nbsp;ROLE_ADMIN:<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;extends: []<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;route: ^admin<br>
</code>

/**
This package is a reusable authentification template : JWT access toke, rotation refresh token, CSRF protection, cookies handling

Required: 
-one adapter implements AuthUserService(loadUserByUsername and loadUserById), returning AuthUser object(DefaultAuthUser). 
Optional:
-ProjectSecurityRules bean for project specefic URL rules.

Copy this package unchanged, anything project-specefic belongs outside it.
**/

package com.example.demo.security;

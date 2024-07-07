import jwt
from datetime import datetime, timedelta
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.test import APITestCase

import sys
import os


User = get_user_model()

class TokenGenerationTestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='password123',
            firstName='John',
            lastName='Doe',
        )

    def test_token_expiry(self):
        refresh = RefreshToken.for_user(self.user)
        token = str(refresh.access_token)
        
        decoded_payload = jwt.decode(token, options={"verify_signature": False})

        exp_timestamp = decoded_payload['exp']
        exp_datetime = datetime.fromtimestamp(exp_timestamp)
        
        expected_expiry = datetime.now() + timedelta(hours=1)
        
        self.assertLessEqual(exp_datetime, expected_expiry)
        self.assertEqual(decoded_payload['userId'], self.user.userId)



from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from core.models import Organisation

User = get_user_model()

class OrganizationTestCase(APITestCase):

    def get_access_token(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def test_organization_access_on_registration(self):
        # Register a user and automatically add them to an organization
        register_url = reverse('register')
        register_data = {
            'email': 'test@example.com',
            'password': 'password123',
            'firstName': 'John',
            'lastName': 'Doe',
        }
        response = self.client.post(register_url, register_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Retrieve the created user
        user = User.objects.get(email=register_data['email'])

        # Get JWT access token for the registered user
        access_token = self.get_access_token(user)
        
        # Make authenticated request with JWT token to fetch organisations
        url = reverse('organisation-list')
        auth_header = {'HTTP_AUTHORIZATION': f'Bearer {access_token}'}
        response = self.client.get(url, **auth_header)
        
        # Assert the response status code and expected data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['data']['organisations']), 1)

        # Create an extra organization
        extra_organization = Organisation.objects.create(name='Extra Org')

        # Fetch organizations again to check access
        response = self.client.get(url, **auth_header)

        # Assert that the extra organization is not visible
        self.assertNotIn(extra_organization.orgId, [org['orgId'] for org in response.data['data']['organisations']])


class AuthEndpointTests(APITestCase):
    
    def setUp(self):
        # Create a user for testing duplicate email scenario
        self.user = User.objects.create_user(
            email='test2@example.com',
            password='password123',
            firstName='John',
            lastName='Doe',
        )

    def get_access_token(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def test_register_user_success(self):
        url = reverse('register')
        data = {
            'email': 'test@example.com',
            'password': 'password123',
            'firstName': 'John',
            'lastName': 'Doe',
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify default organisation name is correctly generated
        user = User.objects.get(email=data['email'])
        default_org_name = f"{user.firstName}'s Organisation"
        self.assertEqual(user.organisations.first().name, default_org_name)
        
        # Check response contains expected user details and access token
        self.assertIn('accessToken', response.data['data'])
        self.assertEqual(response.data['data']['user']['email'], data['email'])
        self.assertEqual(response.data['data']['user']['firstName'], data['firstName'])
        self.assertEqual(response.data['data']['user']['lastName'], data['lastName'])


    def test_login_user_success(self):
        
        register_url = reverse('register')
        register_data = {
            'email': 'test@example.com',
            'password': 'password123',
            'firstName': 'John',
            'lastName': 'Doe',
        }
        self.client.post(register_url, register_data, format='json')

        # Now attempt to log in with the registered user
        url = reverse('login')
        login_data = {
            'email': 'test@example.com',
            'password': 'password123',
        }
        response = self.client.post(url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check response contains expected user details and access token
        self.assertIn('accessToken', response.data['data'])
        self.assertEqual(response.data['data']['user']['email'], login_data['email'])
        self.assertEqual(response.data['data']['user']['firstName'], register_data['firstName'])
        self.assertEqual(response.data['data']['user']['lastName'], register_data['lastName'])


    def test_missing_first_name(self):
        url = reverse('register')
        data = {
            'lastName': 'Doe',
            'email': 'test@example.com',
            'password': 'password123',
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertIn('firstName', [error['field'] for error in response.data['errors']])
    
    def test_missing_last_name(self):
        url = reverse('register')
        data = {
            'firstName': 'John',
            'email': 'test@example.com',
            'password': 'password123',
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertIn('lastName', [error['field'] for error in response.data['errors']])
    
    def test_missing_email(self):
        url = reverse('register')
        data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'password': 'password123',
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertIn('email', [error['field'] for error in response.data['errors']])
    
    def test_missing_password(self):
        url = reverse('register')
        data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'test@example.com',
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertIn('password', [error['field'] for error in response.data['errors']])


    def test_duplicate_email(self):
        url = reverse('register')
        data = {
            'firstName': 'Jane',
            'lastName': 'Doe',
            'email': 'test2@example.com',  # Duplicate email
            'password': 'password456',
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(len(response.data['errors']), 1)
        self.assertEqual(response.data['errors'][0]['field'], 'email')
        self.assertEqual(response.data['errors'][0]['message'], 'user with this email already exists.')
        
        
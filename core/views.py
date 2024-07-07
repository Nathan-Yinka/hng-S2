from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError
from .models import Organisation
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer, OrganisationSerializer
from .utils import standard_response,format_validation_errors

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as exc:
            return Response({
                "errors": format_validation_errors(exc.detail)
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        response = standard_response('success', 'Registration successful', {
                'accessToken': str(refresh.access_token),
                'user': UserSerializer(user).data
            })
        
        return Response(response, status=status.HTTP_201_CREATED)

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as exc:
            return Response({
                "errors": format_validation_errors(exc.detail)
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        
        user = serializer.validated_data['user']
         
        if user:
            refresh = RefreshToken.for_user(user)
            response = standard_response('success', 'Login successful', {
                    'accessToken': str(refresh.access_token),
                    'user': UserSerializer(user).data
                })
            return Response(response, status=status.HTTP_200_OK)
        
        else:
            return Response({
                'status': 'Bad request',
                'message': 'Authentication failed',
                'statusCode': 401
            }, status=status.HTTP_401_UNAUTHORIZED)


class UserDetailView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(standard_response(
            status="success",
            message="User retrieved successfully",
            data=serializer.data
        ), status=status.HTTP_200_OK)

class OrganisationListView(generics.ListCreateAPIView):
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return self.request.user.organisations.all()
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(standard_response(
            status="success",
            message="Organisations retrieved successfully",
            data={"organisations": serializer.data}
        ), status=status.HTTP_200_OK)
        
    def perform_create(self, serializer):
        organisation = serializer.save()
        organisation.users.add(self.request.user)
        return organisation

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as exc:
            return Response({"errors": exc.detail}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        organisation = self.perform_create(serializer)
        return Response(standard_response(
            status="success",
            message="Organisation created successfully",
            data={
                "orgId": organisation.orgId,
                "name": organisation.name,
                "description": organisation.description
            }
        ), status=status.HTTP_201_CREATED)

class OrganisationDetailView(generics.RetrieveAPIView):
    queryset = Organisation.objects.all()
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated]
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(standard_response(
            status="success",
            message="Organisation retrieved successfully",
            data=serializer.data
        ), status=status.HTTP_200_OK)



class AddUserToOrganisationView(generics.GenericAPIView):

    def post(self, request, orgId):
        try:
            organisation = get_object_or_404(Organisation, orgId=orgId)
            user_id = request.data.get('userId')

            if not user_id:
                return Response(standard_response(
                    status="error",
                    message="userId is required",
                ), status=status.HTTP_400_BAD_REQUEST)

            user = get_object_or_404(User, userId=user_id)
            
            if organisation.users.filter(userId=user.userId).exists():
                return Response(standard_response(
                    status="error",
                    message="User already belongs to this organisation",
                ), status=status.HTTP_400_BAD_REQUEST)

            organisation.users.add(user)
            organisation.save()

            return Response(standard_response(
                status="success",
                message="User added to organisation successfully",
                data={}
            ), status=status.HTTP_200_OK)
        except ValueError as e:
            return Response(standard_response(
                    status="error",
                    message=str(e),
                ), status=status.HTTP_400_BAD_REQUEST)

from django.contrib.auth.hashers import check_password, make_password
from django.shortcuts import render, redirect,get_object_or_404
from django.db.models import Q
from django.core.mail import send_mail
from django.contrib import messages
from .models import User, BMIRecord, Specialist
import random
# ---------------- HOME  AND ABOUT----------------
def index(request):
    return render(request, 'index.html')

def about(request):
    return render(request, 'about.html')




# ---------------- REGISTER ----------------
def register(request):
    if request.method == 'POST':
        name = request.POST.get('username')
        email = request.POST.get('email')
        age = request.POST.get('age')
        gender = request.POST.get('gender')
        city = request.POST.get('city')  # ✅ new
        has_condition = request.POST.get('has_condition')  # "Yes" or "No"
        condition = request.POST.get('condition') if has_condition == 'Yes' else None
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Age validation
        try:
            age = int(age)
        except (TypeError, ValueError):
            messages.error(request, 'Please enter a valid age.')
            return redirect('register')
        if age < 15 or age > 100:
            messages.error(request, 'Age must be between 15 and 100 years.')
            return redirect('register')

        # Gender required
        if not gender:
            messages.error(request, 'Please select your gender.')
            return redirect('register')

        # City required
        if not city:
            messages.error(request, 'Please select your city.')
            return redirect('register')

        # Confirm password
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')

        # Email uniqueness
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email is already registered.')
            return redirect('register')

        # Generate OTP
        otp = str(random.randint(100000, 999999))

        # Send OTP
        try:
            send_mail(
                subject='Your OTP Code for BMI Calculator',
                message=f'Hello {name},\n\nYour OTP code is: {otp}',
                from_email='your_email@gmail.com',
                recipient_list=[email],
                fail_silently=False,
            )
        except Exception as e:
            messages.error(request, f"Could not send OTP email. Please try again later. ({e})")
            return redirect('register')

        # Save user
        user = User(
            name=name,
            email=email,
            password=make_password(password),
            age=age,
            gender=gender,
            city=city,  # ✅ required
            has_condition=(has_condition == 'Yes'),  # ✅ optional toggle
            condition=condition,  # ✅ optional
            otp_code=otp,
            is_verified=False
        )
        user.save()

        # Store email in session
        request.session['email'] = email
        messages.success(request, 'Registration successful! Please check your email for OTP.')
        return redirect('verify')

    return render(request, 'register.html')





# ---------------- LOGIN ----------------


def login(request):
    # Clear any previous session
    request.session.pop('user_name', None)
    request.session.pop('user_id', None)

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'Invalid Email. Please try again.')
            return redirect('login')

        if not check_password(password, user.password):
            messages.error(request, 'Invalid Password. Please try again.')
            return redirect('login')

        if not user.is_verified:
            messages.error(request, 'Account not verified. Please check your email for OTP.')
            return redirect('login')

        # ✅ Save session
        request.session['user_id'] = user.id
        request.session['user_name'] = user.name
        messages.success(request, f'Welcome back, {user.name}!')

        # ✅ Redirect based on admin flag
        if user.admin:   # if admin column is True (1)
            return redirect('admin_home')   # goes to admin.html
        else:
            return redirect('user')    # goes to user.html

    return render(request, 'login.html')




# ---------------- FORGET PASSWORD ----------------
def forget(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'Email not found.')
            return redirect('forgetPass')

        otp = str(random.randint(100000, 999999))
        user.otp_code = otp
        user.save()

        try:
            send_mail(
                subject='Password Reset OTP - BMI Calculator',
                message=f'Hello,\n\nYour OTP for password reset is: {otp}',
                from_email='your_email@gmail.com',
                recipient_list=[email],
                fail_silently=False,
            )
        except Exception as e:
            messages.error(request, f"Could not send OTP email. Please try again later. ({e})")
            return redirect('forgetPass')

        request.session['reset_email'] = email
        messages.success(request, 'OTP sent to your email.')
        return redirect('verify')

    return render(request, 'forget.html')





# ---------------- VERIFY OTP ----------------
def verify(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')

        if 'reset_email' in request.session:   # check reset first
            email = request.session['reset_email']
            flow = 'reset'
        elif 'email' in request.session:
            email = request.session['email']
            flow = 'register'
        else:
            messages.error(request, 'Session expired. Please start again.')
            return redirect('register')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('register')

        if user.otp_code == otp:
            user.otp_code = None
            if flow == 'reset':
                user.save()
                messages.success(request, 'OTP verified. You can now change your password.')
                return redirect('changePass')
            else:
                user.is_verified = True
                user.save()
                messages.success(request, 'Account verified successfully! Please log in.')
                return redirect('login')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
            return redirect('verify')

    return render(request, 'verify.html')





# ---------------- CHANGE PASSWORD ----------------
def changePass(request):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        email = request.session.get('reset_email')

        if not email:
            messages.error(request, 'Session expired. Please start again.')
            return redirect('forgetPass')

        if new_password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('changePass')

        if len(new_password) < 6 or not any(c.isalpha() for c in new_password) or not any(c.isdigit() for c in new_password):
            messages.error(request, 'Password must be at least 6 characters and contain both letters and numbers.')
            return redirect('changePass')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('forgetPass')

        user.password = make_password(new_password)
        user.save()

        del request.session['reset_email']
        messages.success(request, 'Password changed successfully. Please log in with your new password.')
        return redirect('login')

    return render(request, 'changePass.html')





# ---------------- USER HOME ----------------
def user_home(request):
    if 'user_id' not in request.session:
        messages.error(request, 'Please log in first.')
        return redirect('login')
    return render(request, 'user.html')




# ----------------LOGOUT USER HOME ----------------
def logout(request):
    request.session.flush()
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')




# ---------------- BMI CALCULATOR ----------------
def calculate_bmi(request):
    if request.method == 'POST':
        try:
            height = float(request.POST.get('height'))
            weight = float(request.POST.get('weight'))

            if height < 55 or height > 272:
                messages.error(request, "Please enter valid height.")
                return redirect('calculate_bmi')
            if weight < 25 or weight > 150:
                messages.error(request, "Please enter valid weight.")
                return redirect('calculate_bmi')

            bmi = round(weight / ((height / 100) ** 2), 2)

            if bmi < 18.5:
                status = "Underweight"
            elif 18.5 <= bmi < 24.9:
                status = "Normal"
            elif 25 <= bmi < 29.9:
                status = "Overweight"
            else:
                status = "Obese"

            user_condition = None
            if 'user_id' in request.session:
                user = User.objects.get(id=request.session['user_id'])
                BMIRecord.objects.create(
                    user=user,
                    height=height,
                    weight=weight,
                    bmi=bmi,
                    status=status
                )
                # ✅ capture condition from user model
                user_condition = user.condition  

            messages.success(request, f'Your BMI was calculated successfully: {bmi} ({status}).')
            return render(request, 'calculate_bmi.html', {
                'bmi': bmi,
                'status': status,
                'height': height,
                'weight': weight,
                'condition': user_condition  # ✅ pass condition to template
            })
        except ValueError:
            messages.error(request, "Invalid input. Please enter numbers only.")
            return redirect('calculate_bmi')

    return render(request, 'calculate_bmi.html')




# ---------------- TRACK PROGRESS ----------------
def track_progress(request):
    if 'user_id' not in request.session:
        messages.error(request, "Please log in first.")
        return redirect('login')

    user = User.objects.get(id=request.session['user_id'])
    records = user.bmi_records.order_by('created_at')
    return render(request, 'track_progress.html', {'records': records})




def diet_plan(request, status):
    return render(request, 'diet.html', {'status': status})

def diet_diabetes(request, status):
    
    return render(request, 'diet_diabetes.html', {'status': status})

def diet_bp(request, status):
    
    return render(request, 'diet_bp.html', {'status': status})


def workout_plan(request, status):
    return render(request, 'workout.html', {'status': status})



def admin_home(request):
    return render(request, 'admin.html')


def manage_users(request):
    users = User.objects.all()
    return render(request, 'manage_user.html', {'users': users})


def verify_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_verified = True
    user.save()
    messages.success(request, f'User {user.name} has been verified.')
    return redirect('manage_users')


def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.delete()
    messages.success(request, f'User {user.name} has been deleted.')
    return redirect('manage_users')




def make_admin(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.admin = True
    user.save()
    messages.success(request, f'User {user.name} is now an Admin.')
    return redirect('manage_users')







def specialist_bot(request):
    # Session auth
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        # Clear bad session and force login
        request.session.pop('user_id', None)
        request.session.pop('user_name', None)
        return redirect('login')

    # Latest BMI record (optional)
    bmi_record = BMIRecord.objects.filter(user=user).order_by('-created_at').first()
    bmi_status = (bmi_record.status if bmi_record and getattr(bmi_record, 'status', None) else None)

    # Normalize user fields (avoid None in template/JS)
    user_city = (user.city or "").strip()
    user_condition = (user.condition if getattr(user, 'has_condition', False) else None)

   
    specialists = Specialist.objects.all()

  
    context = {
        "specialists": specialists,
        "bmi_status": bmi_status,   # optional: can be shown in intro
        "condition": user_condition,
        "city": user_city,
    }
    return render(request, "bot.html", context)

from django.http import HttpResponse
from django.template.loader import render_to_string
from xhtml2pdf import pisa
from .models import User, BMIRecord, Specialist

def download_report(request):
    # 1. Check for manual session
    user_id = request.session.get('user_id')
    if not user_id:
        return HttpResponse("Unauthorized: Please log in first.", status=401)

    try:
        # 2. Fetch User and latest BMI Record
        current_user = User.objects.get(id=user_id)
        latest_record = BMIRecord.objects.filter(user=current_user).latest('created_at')
        
        # 3. Define Variables
        status = latest_record.status  # Underweight, Normal, Overweight, Obese
        # Normalize condition to "No" if it is empty or None
        condition = current_user.condition if current_user.condition and current_user.condition != "None" else "No"
        user_city = current_user.city
        
        # 4. Specialist Filtering Logic (Strict Requirement Match)
        search_categories = []
        
        if status == "Normal":
            if condition == "No":
                # Scenario: Normal and No Condition -> General
                search_categories.append("General")
            else:
                # Scenario: Normal but has condition -> Condition based only
                search_categories.append(condition)
        else:
            # Scenario: Weight issue (Underweight, Overweight, Obese)
            
            # Map Obese to Overweight for specialist matching
            weight_tag = "Overweight" if status == "Obese" else status
            search_categories.append(weight_tag)
            
            # If they also have a condition -> Add the condition category too
            if condition != "No":
                search_categories.append(condition)

        # Query the database based on the logic-built list
        recommended_specialists = Specialist.objects.filter(
            location__iexact=user_city,
            specialist_type__in=search_categories
        )

        # 5. Prepare Context for PDF
        context = {
            'user': current_user,
            'record': latest_record,
            'status': status,
            'condition': condition,
            'specialists': recommended_specialists,
        }

        # 6. Render HTML to PDF
        # Ensure your template filename is 'report.html' as used below
        html_string = render_to_string('report.html', context)
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{current_user.name}_Health_Report.pdf"'

        pisa_status = pisa.CreatePDF(html_string, dest=response)
        
        if pisa_status.err:
            return HttpResponse('Error generating PDF', status=500)
            
        return response

    except User.DoesNotExist:
        return HttpResponse("User not found.", status=404)
    except BMIRecord.DoesNotExist:
        return HttpResponse("No BMI records found. Please calculate your BMI first.")
    except Exception as e:
        return HttpResponse(f"An unexpected error occurred: {e}", status=500)
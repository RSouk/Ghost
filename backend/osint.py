import requests
import time
import os
from dotenv import load_dotenv
from database import get_db, Profile, Breach

load_dotenv()

def check_hibp_breaches(email):
    """
    Check Have I Been Pwned for breaches
    Returns list of breaches and total count
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        'User-Agent': 'Ghost-OSINT-Platform',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # 404 means no breaches found
        if response.status_code == 404:
            return [], 0
        
        # 200 means breaches found
        if response.status_code == 200:
            breaches = response.json()
            return breaches, len(breaches)
        
        # 429 means rate limited
        if response.status_code == 429:
            return None, -1
        
        return None, -2
        
    except Exception as e:
        print(f"Error checking HIBP: {e}")
        return None, -3

def scan_profile_breaches(profile_id):
    """
    Scan a profile for breaches and update database
    Returns dict with results
    """
    db = get_db()
    profile = db.query(Profile).filter(Profile.id == profile_id).first()
    
    if not profile or not profile.email:
        db.close()
        return {'error': 'Profile not found or no email'}
    
    print(f"Scanning {profile.email} for breaches...")
    breaches, count = check_hibp_breaches(profile.email)
    
    if count == -1:
        db.close()
        return {'error': 'Rate limited. Wait 6 seconds and try again.'}
    
    if count == -2:
        db.close()
        return {'error': 'API error occurred'}
    
    if count == -3:
        db.close()
        return {'error': 'Network error'}
    
    if breaches is None:
        db.close()
        return {'error': 'Unknown error occurred'}
    
    # Clear old breach data for this profile
    db.query(Breach).filter(Breach.profile_id == profile_id).delete()
    
    # Add new breach data
    if count > 0:
        for breach in breaches:
            new_breach = Breach(
                profile_id=profile_id,
                breach_name=breach.get('Name'),
                breach_date=breach.get('BreachDate'),
                data_classes=', '.join(breach.get('DataClasses', []))
            )
            db.add(new_breach)
    
    # Update profile breach count and risk score
    profile.breach_count = count
    
    # Calculate risk score based on breaches
    # Base score: 10 points per breach, capped at 100
    breach_score = min(count * 10, 60)
    
    # Add points for sensitive data types
    sensitive_score = 0
    if count > 0:
        for breach in breaches:
            data_classes = breach.get('DataClasses', [])
            if 'Passwords' in data_classes:
                sensitive_score += 15
            if 'Credit cards' in data_classes or 'Bank account numbers' in data_classes:
                sensitive_score += 20
            if 'Social security numbers' in data_classes:
                sensitive_score += 25
    
    profile.risk_score = min(breach_score + sensitive_score, 100)
    
    db.commit()
    
    result = {
        'profile_id': profile_id,
        'email': profile.email,
        'breaches_found': count,
        'risk_score': profile.risk_score,
        'breaches': [{
            'name': b.get('Name'),
            'date': b.get('BreachDate'),
            'data_types': b.get('DataClasses', [])
        } for b in breaches] if breaches else []
    }
    
    db.close()
    print(f"Scan complete: {count} breaches found")
    return result

def calculate_risk_score(profile_id):
    """
    Calculate overall risk score for a profile
    Based on multiple factors
    """
    db = get_db()
    profile = db.query(Profile).filter(Profile.id == profile_id).first()
    
    if not profile:
        db.close()
        return 0
    
    score = 0
    
    # Breach score (0-60 points)
    score += min(profile.breach_count * 10, 60)
    
    # Social media exposure (0-20 points) - TODO: implement when we add social media scanning
    # Device exposure (0-20 points) - TODO: implement when we add device scanning
    
    profile.risk_score = min(score, 100)
    db.commit()
    db.close()
    
    return profile.risk_score
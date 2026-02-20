from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
from datetime import datetime, date, timedelta
import json
import logging
import re

from src.database import db, ManagedUser, UserTimeUsage, Settings, UserWeeklySchedule, UserDailyTimeInterval
from src.ssh_helper import SSHClient
from src.task_manager import BackgroundTaskManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///timekpr.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db.init_app(app)

# Initialize background task manager
task_manager = BackgroundTaskManager()
task_manager.init_app(app)

# Load app configuration once
config_path = os.path.join(os.path.dirname(__file__), 'config.json')
try:
    with open(config_path, 'r') as f:
        app_config = json.load(f)
except Exception as e:
    logging.warning(f"Impossibile leggere config.json: {e}. Uso valori di default.")
    app_config = {}

# Admin username loaded from config (fallback: admin)
ADMIN_USERNAME = app_config.get('admin_username', 'admin')

def _sync_weekly_schedule_from_remote_config(user, config_dict):
    """Try to update local weekly schedule from remote timekpr config."""
    if not config_dict:
        return False

    allowed_days_keys = [
        'ALLOWED_WEEKDAYS',
        'ALLOWED_DAYS',
        'DAYS_ALLOWED',
        'WEEK_ALLOWED_DAYS'
    ]
    time_limits_keys = [
        'LIMITS_PER_WEEKDAYS',
        'TIME_LIMITS',
        'TIMELIMITS',
        'DAILY_LIMITS',
        'LIMITS_PER_DAY',
        'LIMITS'
    ]

    allowed_days = None
    time_limits = None

    for key in allowed_days_keys:
        if key in config_dict:
            allowed_days = config_dict.get(key)
            break

    for key in time_limits_keys:
        if key in config_dict:
            time_limits = config_dict.get(key)
            break

    if not allowed_days or not time_limits:
        return False

    try:
        if not isinstance(allowed_days, list):
            allowed_days = [allowed_days]
        if not isinstance(time_limits, list):
            time_limits = [time_limits]

        allowed_days = [int(day) for day in allowed_days]
        time_limits = [int(limit) for limit in time_limits]
    except (ValueError, TypeError):
        return False

    if not user.weekly_schedule:
        schedule = UserWeeklySchedule(user_id=user.id)
        db.session.add(schedule)
        db.session.flush()
        user.weekly_schedule = schedule
    else:
        schedule = user.weekly_schedule

    schedule_hours = {
        'monday': 0,
        'tuesday': 0,
        'wednesday': 0,
        'thursday': 0,
        'friday': 0,
        'saturday': 0,
        'sunday': 0
    }
    day_names = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']

    for index, day_number in enumerate(allowed_days):
        if index >= len(time_limits):
            break
        if 1 <= day_number <= 7:
            schedule_hours[day_names[day_number - 1]] = round(time_limits[index] / 3600, 2)

    schedule.set_schedule_from_dict(schedule_hours)
    schedule.mark_synced()
    return True

def _parse_allowed_hours_interval(raw_value):
    """Parse timekpr ALLOWED_HOURS_X value and return (start_h, start_m, end_h, end_m, is_enabled)."""
    if raw_value is None:
        return None

    if isinstance(raw_value, list):
        tokens = [str(token).strip() for token in raw_value if str(token).strip()]
    else:
        tokens = [token.strip() for token in str(raw_value).split(';') if token.strip()]

    if not tokens:
        return None

    ranges = []
    for token in tokens:
        match = re.match(r'^(\d{1,2})(?:\[(\d{1,2})-(\d{1,2})\])?$', token)
        if not match:
            continue

        hour = int(match.group(1))
        start_minute = int(match.group(2)) if match.group(2) is not None else 0
        end_minute = int(match.group(3)) if match.group(3) is not None else 59

        if not (0 <= hour <= 23 and 0 <= start_minute <= 59 and 0 <= end_minute <= 59):
            continue
        if start_minute > end_minute:
            continue

        start_total = hour * 60 + start_minute
        end_total = hour * 60 + end_minute
        ranges.append((start_total, end_total))

    if not ranges:
        return None

    ranges.sort(key=lambda value: value[0])
    merged = [ranges[0]]
    for current_start, current_end in ranges[1:]:
        last_start, last_end = merged[-1]
        if current_start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, current_end))
        else:
            merged.append((current_start, current_end))

    full_day_access = len(merged) == 1 and merged[0][0] == 0 and merged[0][1] == 1439
    if full_day_access:
        return 9, 0, 17, 0, False

    start_total, end_total = merged[0][0], merged[-1][1]

    # Convert inclusive remote end minute to boundary-style end time for UI
    # Example: remote 22:59 becomes UI 23:00
    if end_total < 1439:
        end_total += 1
    start_hour, start_minute = divmod(start_total, 60)
    end_hour, end_minute = divmod(end_total, 60)

    return start_hour, start_minute, end_hour, end_minute, True

def _sync_intervals_from_remote_config(user, config_dict):
    """Sync ALLOWED_HOURS_X from remote config into local intervals table."""
    if not config_dict:
        return False

    synced_any = False
    for day_of_week in range(1, 8):
        key = f'ALLOWED_HOURS_{day_of_week}'
        if key not in config_dict:
            continue

        parsed = _parse_allowed_hours_interval(config_dict.get(key))
        if parsed is None:
            continue

        start_hour, start_minute, end_hour, end_minute, is_enabled = parsed

        interval = UserDailyTimeInterval.query.filter_by(
            user_id=user.id,
            day_of_week=day_of_week
        ).first()

        if not interval:
            interval = UserDailyTimeInterval(
                user_id=user.id,
                day_of_week=day_of_week,
                start_hour=start_hour,
                start_minute=start_minute,
                end_hour=end_hour,
                end_minute=end_minute,
                is_enabled=is_enabled
            )
            db.session.add(interval)
        else:
            interval.start_hour = start_hour
            interval.start_minute = start_minute
            interval.end_hour = end_hour
            interval.end_minute = end_minute
            interval.is_enabled = is_enabled

        interval.mark_synced()
        synced_any = True

    return synced_any

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check admin password using hash comparison
        if username == ADMIN_USERNAME and Settings.check_admin_password(password):
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
            flash(error, 'danger')
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    # Get all valid users - make sure we're getting fresh data by expiring SQLAlchemy's cache
    db.session.expire_all()
    users = ManagedUser.query.filter_by(is_valid=True).all()
    
    # Track users with pending time adjustments
    pending_adjustments = {}
    
    # Prepare user data for the dashboard
    user_data = []
    for user in users:
        # Get usage data for charts
        usage_data = user.get_recent_usage(days=7)
        
        # Get time left today if available
        time_left = user.get_config_value('TIME_LEFT_DAY')
        if time_left is not None:
            time_left_hours = time_left // 3600
            time_left_minutes = (time_left % 3600) // 60
            time_left_formatted = f"{time_left_hours}h {time_left_minutes}m"
        else:
            time_left_formatted = "Unknown"
        
        # Do NOT format last_checked time - pass the datetime object directly
        # So the template can format it
        
        # Check for pending time adjustments
        if user.pending_time_adjustment is not None and user.pending_time_operation is not None:
            minutes = user.pending_time_adjustment // 60
            operation = user.pending_time_operation
            pending_adjustments[str(user.id)] = f"{operation}{minutes} minutes"
        
        user_data.append({
            'id': user.id,
            'username': user.username,
            'system_ip': user.system_ip,
            'last_checked': user.last_checked,  # Keep as datetime object
            'usage_data': usage_data,
            'time_left': time_left_formatted,
            'weekly_schedule': user.weekly_schedule
        })
    
    return render_template('dashboard.html', users=user_data, pending_adjustments=pending_adjustments)

@app.route('/admin')
def admin():
    if not session.get('logged_in'):
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    # Get all managed users
    users = ManagedUser.query.all()
    return render_template('admin.html', users=users)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not session.get('logged_in'):
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    # Handle password change
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required', 'danger')
        elif not Settings.check_admin_password(current_password):
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        elif len(new_password) < 4:
            flash('New password must be at least 4 characters long', 'danger')
        else:
            # Update the password with hashing
            Settings.set_admin_password(new_password)
            flash('Password updated successfully', 'success')
            
            # Redirect to avoid form resubmission
            return redirect(url_for('settings'))
    
    return render_template('settings.html')

@app.route('/api/task-status')
def get_task_status():
    """Get the status of the background task manager"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    status = task_manager.get_status()
    return jsonify({
        'success': True,
        'status': status
    })

@app.route('/restart-tasks')
def restart_tasks():
    """Restart the background task manager"""
    if not session.get('logged_in'):
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    task_manager.restart()
    flash('Background tasks restarted', 'success')
    
    # Redirect back to the referring page
    referrer = request.referrer
    if referrer:
        return redirect(referrer)
    else:
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/users/add', methods=['POST'])
def add_user():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    username = request.form.get('username')
    system_ip = request.form.get('system_ip')
    
    if not username or not system_ip:
        flash('Both username and system IP are required', 'danger')
        return redirect(url_for('admin'))
    
    # Check if user already exists
    existing_user = ManagedUser.query.filter_by(username=username, system_ip=system_ip).first()
    
    if existing_user:
        flash(f'User {username} on {system_ip} already exists', 'warning')
        return redirect(url_for('admin'))
    
    # Create new user
    new_user = ManagedUser(username=username, system_ip=system_ip)
    
    # Validate with timekpr
    ssh_client = SSHClient(hostname=system_ip)
    is_valid, message, config_dict = ssh_client.validate_user(username)
    
    new_user.is_valid = is_valid
    new_user.last_checked = datetime.utcnow()
    
    if is_valid and config_dict:
        new_user.last_config = json.dumps(config_dict)
        
        # Add the user to get an ID first
        db.session.add(new_user)
        db.session.commit()
        
        # Add today's usage data
        today = date.today()
        time_spent = config_dict.get('TIME_SPENT_DAY', 0)
        
        usage = UserTimeUsage(
            user_id=new_user.id,
            date=today,
            time_spent=time_spent
        )
        db.session.add(usage)
        db.session.commit()
        
        flash(f'User {username} added and validated successfully', 'success')
    else:
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {username} added but validation failed: {message}', 'warning')
    
    return redirect(url_for('admin'))

@app.route('/users/validate/<int:user_id>')
def validate_user(user_id):
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    user = ManagedUser.query.get_or_404(user_id)
    
    # Validate with timekpr
    ssh_client = SSHClient(hostname=user.system_ip)
    is_valid, message, config_dict = ssh_client.validate_user(user.username)
    
    user.is_valid = is_valid
    user.last_checked = datetime.utcnow()
    
    if is_valid and config_dict:
        user.last_config = json.dumps(config_dict)
        
        # Update today's usage data
        today = date.today()
        time_spent = config_dict.get('TIME_SPENT_DAY', 0)
        
        # Look for an existing record for today
        usage = UserTimeUsage.query.filter_by(
            user_id=user.id,
            date=today
        ).first()
        
        if usage:
            usage.time_spent = time_spent
        else:
            # Create a new record
            usage = UserTimeUsage(
                user_id=user.id,
                date=today,
                time_spent=time_spent
            )
            db.session.add(usage)
        
        db.session.commit()
        flash(f'User {user.username} validated successfully', 'success')
    else:
        db.session.commit()
        flash(f'User validation failed: {message}', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/users/pull-config/<int:user_id>', methods=['POST'])
def pull_user_config(user_id):
    """Pull remote user configuration and save it to local DB."""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    user = ManagedUser.query.get_or_404(user_id)
    ssh_client = SSHClient(hostname=user.system_ip)

    is_valid, message, config_dict = ssh_client.validate_user(user.username)
    user.last_checked = datetime.utcnow()

    if not is_valid or not config_dict:
        db.session.commit()
        flash(f'Failed to pull config for {user.username}: {message}', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    user.is_valid = True
    user.last_config = json.dumps(config_dict)

    today = date.today()
    time_spent = config_dict.get('TIME_SPENT_DAY', 0)
    usage = UserTimeUsage.query.filter_by(user_id=user.id, date=today).first()
    if usage:
        usage.time_spent = time_spent
    else:
        db.session.add(UserTimeUsage(user_id=user.id, date=today, time_spent=time_spent))

    schedule_synced = _sync_weekly_schedule_from_remote_config(user, config_dict)
    intervals_synced = _sync_intervals_from_remote_config(user, config_dict)
    db.session.commit()

    if schedule_synced and intervals_synced:
        flash(f'Pulled remote config for {user.username} and updated schedule + intervals', 'success')
    elif schedule_synced:
        flash(f'Pulled remote config for {user.username} and updated local schedule', 'success')
    elif intervals_synced:
        flash(f'Pulled remote config for {user.username} and updated local intervals', 'success')
    else:
        flash(f'Pulled remote config for {user.username}', 'success')

    return redirect(request.referrer or url_for('dashboard'))

@app.route('/users/push-config/<int:user_id>', methods=['POST'])
def push_user_config(user_id):
    """Push local user configuration to remote timekpr."""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    user = ManagedUser.query.get_or_404(user_id)
    ssh_client = SSHClient(hostname=user.system_ip)

    messages = []
    has_success = False

    if user.weekly_schedule:
        schedule_dict = user.weekly_schedule.get_schedule_dict()
        success, message = ssh_client.set_weekly_time_limits(user.username, schedule_dict)
        if success:
            user.weekly_schedule.mark_synced()
            has_success = True
            messages.append('weekly limits synced')
        else:
            messages.append(f'weekly limits failed: {message}')

    intervals = UserDailyTimeInterval.query.filter_by(user_id=user.id).all()
    if intervals:
        intervals_dict = {interval.day_of_week: interval for interval in intervals}
        success, message = ssh_client.set_allowed_hours(user.username, intervals_dict)
        if success:
            for interval in intervals:
                interval.mark_synced()
            has_success = True
            messages.append('allowed hours synced')
        else:
            messages.append(f'allowed hours failed: {message}')

    if not user.weekly_schedule and not intervals:
        flash(f'No local config to push for {user.username}', 'warning')
        return redirect(request.referrer or url_for('dashboard'))

    is_valid, _, config_dict = ssh_client.validate_user(user.username)
    if is_valid and config_dict:
        user.last_checked = datetime.utcnow()
        user.last_config = json.dumps(config_dict)
        today = date.today()
        time_spent = config_dict.get('TIME_SPENT_DAY', 0)
        usage = UserTimeUsage.query.filter_by(user_id=user.id, date=today).first()
        if usage:
            usage.time_spent = time_spent
        else:
            db.session.add(UserTimeUsage(user_id=user.id, date=today, time_spent=time_spent))

    db.session.commit()

    if has_success:
        flash(f'Pushed config for {user.username}: {"; ".join(messages)}', 'success')
    else:
        flash(f'Failed to push config for {user.username}: {"; ".join(messages)}', 'danger')

    return redirect(request.referrer or url_for('dashboard'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    user = ManagedUser.query.get_or_404(user_id)
    username = user.username
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} removed successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/api/user/<int:user_id>/usage')
def get_user_usage(user_id):
    """API endpoint to get user usage data"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    user = ManagedUser.query.get_or_404(user_id)
    days = request.args.get('days', 7, type=int)
    
    usage_data = user.get_recent_usage(days=days)
    
    # Format for chart.js
    labels = list(usage_data.keys())
    values = list(usage_data.values())
    
    # Convert seconds to hours for better readability
    values_hours = [round(v / 3600, 1) for v in values]
    
    return jsonify({
        'success': True,
        'labels': labels,
        'values': values_hours,
        'username': user.username
    })

@app.route('/weekly-schedule/<int:user_id>')
def weekly_schedule_user(user_id):
    """Display weekly schedule management page for a specific user"""
    if not session.get('logged_in'):
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    # Get the specific user
    user = ManagedUser.query.get_or_404(user_id)
    
    # Ensure the user has a weekly schedule record
    if not user.weekly_schedule:
        schedule = UserWeeklySchedule(user_id=user.id)
        db.session.add(schedule)
        db.session.commit()
    
    return render_template('weekly_schedule_single.html', user=user)

@app.route('/weekly-schedule/update', methods=['POST'])
def update_weekly_schedule():
    """Update weekly schedule for a user"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    user_id = request.form.get('user_id')
    
    if not user_id:
        flash('User ID is required', 'danger')
        return redirect(url_for('weekly_schedule'))
    
    try:
        user_id = int(user_id)
    except ValueError:
        flash('Invalid user ID', 'danger')
        return redirect(url_for('weekly_schedule'))
    
    user = ManagedUser.query.get_or_404(user_id)
    
    # Get schedule data from form
    schedule_data = {}
    days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    
    for day in days:
        hours = request.form.get(day, '0')
        try:
            hours = float(hours)
            if hours < 0:
                hours = 0
            elif hours > 24:
                hours = 24
        except (ValueError, TypeError):
            hours = 0
        schedule_data[day] = hours  # Store as float hours to support fractional hours
    
    # Get or create weekly schedule
    if not user.weekly_schedule:
        schedule = UserWeeklySchedule(user_id=user.id)
        db.session.add(schedule)
        db.session.flush()  # Get the ID
        user.weekly_schedule = schedule
    else:
        schedule = user.weekly_schedule
    
    # Update the schedule
    schedule.set_schedule_from_dict(schedule_data)
    
    try:
        db.session.commit()
        flash(f'Weekly schedule updated for {user.username}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating schedule: {str(e)}', 'danger')
    
    return redirect(url_for('weekly_schedule_user', user_id=user.id))

@app.route('/api/user/<int:user_id>/intervals')
def get_user_intervals(user_id):
    """API endpoint to get user time intervals"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    user = ManagedUser.query.get_or_404(user_id)
    
    # Get all intervals for this user
    intervals = UserDailyTimeInterval.query.filter_by(user_id=user.id).all()
    
    # Format intervals by day
    intervals_dict = {}
    for interval in intervals:
        intervals_dict[interval.day_of_week] = {
            'id': interval.id,
            'day_name': interval.get_day_name(),
            'start_hour': interval.start_hour,
            'start_minute': interval.start_minute,
            'end_hour': interval.end_hour,
            'end_minute': interval.end_minute,
            'is_enabled': interval.is_enabled,
            'is_synced': interval.is_synced,
            'time_range': interval.get_time_range_string(),
            'last_synced': interval.last_synced.strftime('%Y-%m-%d %H:%M') if interval.last_synced else None
        }
    
    return jsonify({
        'success': True,
        'intervals': intervals_dict,
        'username': user.username
    })

@app.route('/api/user/<int:user_id>/intervals/update', methods=['POST'])
def update_user_intervals(user_id):
    """API endpoint to update user time intervals"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    user = ManagedUser.query.get_or_404(user_id)
    
    try:
        # Get interval data from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        intervals_data = data.get('intervals', {})
        
        for day_str, interval_data in intervals_data.items():
            try:
                day_of_week = int(day_str)
                if not (1 <= day_of_week <= 7):
                    continue

                def parse_hhmm(value):
                    if value is None:
                        return None
                    match = re.match(r'^([01]\d|2[0-3]):([0-5]\d)$', str(value).strip())
                    if not match:
                        return None
                    return int(match.group(1)), int(match.group(2))

                start_hhmm = parse_hhmm(interval_data.get('start_time'))
                end_hhmm = parse_hhmm(interval_data.get('end_time'))

                if interval_data.get('start_time') is not None and start_hhmm is None:
                    return jsonify({
                        'success': False,
                        'message': f'Invalid start time format for day {day_of_week}. Expected HH:MM'
                    }), 400

                if interval_data.get('end_time') is not None and end_hhmm is None:
                    return jsonify({
                        'success': False,
                        'message': f'Invalid end time format for day {day_of_week}. Expected HH:MM'
                    }), 400

                if start_hhmm is not None:
                    start_hour, start_minute = start_hhmm
                else:
                    start_hour = int(interval_data.get('start_hour', 9))
                    start_minute = int(interval_data.get('start_minute', 0))

                if end_hhmm is not None:
                    end_hour, end_minute = end_hhmm
                else:
                    end_hour = int(interval_data.get('end_hour', 17))
                    end_minute = int(interval_data.get('end_minute', 0))

                if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23 and 0 <= start_minute <= 59 and 0 <= end_minute <= 59):
                    return jsonify({
                        'success': False,
                        'message': f'Invalid time values for day {day_of_week}. Hours must be 00-23 and minutes 00-59'
                    }), 400

                is_enabled = bool(interval_data.get('is_enabled', False))

                start_total = start_hour * 60 + start_minute
                end_total = end_hour * 60 + end_minute

                if is_enabled and start_total >= end_total:
                    return jsonify({
                        'success': False,
                        'message': f'Invalid time interval for day {day_of_week}: start time must be before end time'
                    }), 400
                
                # Get or create interval for this day
                interval = UserDailyTimeInterval.query.filter_by(
                    user_id=user.id,
                    day_of_week=day_of_week
                ).first()
                
                if not interval:
                    interval = UserDailyTimeInterval(
                        user_id=user.id,
                        day_of_week=day_of_week
                    )
                    db.session.add(interval)
                
                # Update interval properties
                interval.start_hour = start_hour
                interval.start_minute = start_minute
                interval.end_hour = end_hour
                interval.end_minute = end_minute
                interval.is_enabled = is_enabled
                
                # Validate the interval
                if not interval.is_valid_interval():
                    return jsonify({
                        'success': False,
                        'message': f'Invalid time interval for {interval.get_day_name()}: start time must be before end time'
                    }), 400
                
                # Mark as modified (needs sync)
                interval.mark_modified()
                
            except (ValueError, KeyError) as e:
                return jsonify({
                    'success': False,
                    'message': f'Invalid data format: {str(e)}'
                }), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Time intervals updated for {user.username}',
            'username': user.username
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error updating intervals: {str(e)}'
        }), 500

@app.route('/api/user/<int:user_id>/intervals/sync-status')
def get_intervals_sync_status(user_id):
    """Get sync status of user's time intervals"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    user = ManagedUser.query.get_or_404(user_id)
    
    # Get all intervals for this user
    intervals = UserDailyTimeInterval.query.filter_by(user_id=user.id).all()
    
    # Check if any intervals need sync
    needs_sync = any(not interval.is_synced for interval in intervals)
    
    # Get last sync time (most recent among all intervals)
    last_synced = None
    if intervals:
        synced_intervals = [i for i in intervals if i.last_synced]
        if synced_intervals:
            last_synced = max(i.last_synced for i in synced_intervals)
            last_synced = last_synced.strftime('%Y-%m-%d %H:%M')
    
    # Count enabled vs total intervals
    enabled_count = sum(1 for i in intervals if i.is_enabled)
    total_count = len(intervals)
    
    return jsonify({
        'success': True,
        'needs_sync': needs_sync,
        'last_synced': last_synced,
        'enabled_intervals': enabled_count,
        'total_intervals': total_count,
        'username': user.username
    })

@app.route('/api/schedule-sync-status/<int:user_id>')
def get_schedule_sync_status(user_id):
    """Get the sync status of a user's weekly schedule"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    user = ManagedUser.query.get_or_404(user_id)
    
    if user.weekly_schedule:
        schedule_dict = user.weekly_schedule.get_schedule_dict()
        last_synced = None
        if user.weekly_schedule.last_synced:
            last_synced = user.weekly_schedule.last_synced.strftime('%Y-%m-%d %H:%M')
        
        return jsonify({
            'success': True,
            'is_synced': user.weekly_schedule.is_synced,
            'schedule': schedule_dict,
            'last_synced': last_synced,
            'last_modified': user.weekly_schedule.last_modified.strftime('%Y-%m-%d %H:%M') if user.weekly_schedule.last_modified else None
        })
    else:
        return jsonify({
            'success': True,
            'is_synced': True,  # No schedule means no sync needed
            'schedule': None,
            'last_synced': None,
            'last_modified': None
        })

@app.route('/api/modify-time', methods=['POST'])
def modify_time():
    """Modify time left for a user"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    # Get parameters from request
    user_id = request.form.get('user_id')
    operation = request.form.get('operation')
    seconds = request.form.get('seconds')
    
    if not user_id or not operation or not seconds:
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400
    
    try:
        user_id = int(user_id)
        seconds = int(seconds)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid parameter format'}), 400
    
    # Validate operation
    if operation not in ['+', '-']:
        return jsonify({'success': False, 'message': "Operation must be '+' or '-'"}), 400
    
    # Get user from database
    user = ManagedUser.query.get_or_404(user_id)
    
    # Create SSH client
    ssh_client = SSHClient(hostname=user.system_ip)
    
    # Execute the command
    success, message = ssh_client.modify_time_left(user.username, operation, seconds)
    
    if success:
        # Update user info to reflect changes
        is_valid, _, config_dict = ssh_client.validate_user(user.username)
        if is_valid and config_dict:
            user.last_checked = datetime.utcnow()
            user.last_config = json.dumps(config_dict)
            # Clear any pending adjustments since we succeeded
            user.pending_time_adjustment = None
            user.pending_time_operation = None
            db.session.commit()
            
        return jsonify({
            'success': True,
            'message': message,
            'username': user.username,
            'refresh': True
        })
    else:
        # Store as pending adjustment if it failed
        # First clear any existing pending adjustment
        user.pending_time_adjustment = seconds
        user.pending_time_operation = operation
        db.session.commit()
        
        return jsonify({
            'success': True,  # We report success since we stored it for later
            'message': f"Computer seems to be offline. Time adjustment of {operation}{seconds} seconds has been queued and will be applied when the computer comes online.",
            'username': user.username,
            'pending': True,
            'refresh': True
        })

# With app context
with app.app_context():
    db.create_all()
    print("Database tables verified")
    
    # Initialize admin password if it doesn't exist
    if not Settings.get_value('admin_password_hash', None) and not Settings.get_value('admin_password', None):
        Settings.set_admin_password('admin')
        print("Admin password initialized")
    
    # Start background tasks automatically
    task_manager.start()
    print("Background tasks started automatically")

if __name__ == '__main__':
    # Load host and port from config.json
    host = app_config.get('host', '0.0.0.0')
    port = app_config.get('port', 5000)

    app.run(host=host, port=port, debug=False, use_reloader=False)
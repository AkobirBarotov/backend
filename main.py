import requests
import json
import configparser
import logging
import time
from datetime import datetime, timedelta
import schedule
import threading
from urllib.parse import urlencode
import os
from typing import List, Dict, Optional, Tuple

class HeadHunterBitrixIntegration:
    def __init__(self, config_file='config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file, encoding='utf-8')
        
        # API ma'lumotlari
        self.hh_client_id = self.config.get('HEADHUNTER', 'client_id')
        self.hh_client_secret = self.config.get('HEADHUNTER', 'client_secret')
        self.hh_redirect_uri = self.config.get('HEADHUNTER', 'redirect_uri', fallback='http://localhost:8000/callback')
        
        # Access token ni tekshirish va tozalash
        raw_token = self.config.get('HEADHUNTER', 'access_token', fallback='')
        self.hh_access_token = raw_token.strip() if raw_token and raw_token.strip() != '' else None
        
        # Refresh token
        self.hh_refresh_token = self.config.get('HEADHUNTER', 'refresh_token', fallback='').strip()
        
        # Token expiry tracking
        token_expires_str = self.config.get('HEADHUNTER', 'token_expires_at', fallback='')
        self.token_expires_at = None
        if token_expires_str:
            try:
                self.token_expires_at = datetime.fromisoformat(token_expires_str)
            except ValueError:
                pass
        
        # API base URLs - tashkent uchun API endpoint
        self.hh_api_base = "https://api.hh.ru"  # Global API endpoint
        self.hh_oauth_base = "https://hh.ru"    # Global OAuth endpoint
        
        self.bitrix_webhook = self.config.get('BITRIX24', 'webhook_url')
        
        self.telegram_token = self.config.get('TELEGRAM', 'bot_token')
        self.telegram_chat_id = self.config.get('TELEGRAM', 'chat_id')
        
        # Request session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HH-Bitrix-Integration/2.0 (integration@company.uz)'
        })
        
        # Logging sozlash
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('hh_bitrix.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Processed IDs ni saqlash uchun
        self.processed_ids_file = 'processed_applications.txt'
        self.processed_ids = self.load_processed_ids()
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1.0  # seconds
        
        # Retry configuration
        self.max_retries = 3
        self.retry_delay = 5
        
        # Boshlash vaqtini saqlash
        self.start_time = datetime.now()
    
    def load_processed_ids(self) -> set:
        """Qayta ishlanmasligi uchun ID larni yuklash"""
        try:
            if os.path.exists(self.processed_ids_file):
                with open(self.processed_ids_file, 'r') as f:
                    return set(line.strip() for line in f if line.strip())
            return set()
        except Exception as e:
            self.logger.error(f"ID yuklashda xatolik: {str(e)}")
            return set()
    
    def save_processed_id(self, app_id: str) -> None:
        """ID ni saqlash"""
        try:
            with open(self.processed_ids_file, 'a') as f:
                f.write(f"{app_id}\n")
            self.processed_ids.add(app_id)
        except Exception as e:
            self.logger.error(f"ID saqlashda xatolik: {str(e)}")
            self.send_telegram_error({}, f"ID saqlashda xatolik: {str(e)}")
    
    def save_token_to_config(self, access_token: str, refresh_token: str = None, expires_in: int = None) -> None:
        """Token ma'lumotlarini config faylga saqlash"""
        try:
            self.config.set('HEADHUNTER', 'access_token', access_token)
            if refresh_token:
                self.config.set('HEADHUNTER', 'refresh_token', refresh_token)
            
            if expires_in:
                expires_at = datetime.now() + timedelta(seconds=int(expires_in))
                self.config.set('HEADHUNTER', 'token_expires_at', expires_at.isoformat())
                self.token_expires_at = expires_at
            
            with open('config.ini', 'w', encoding='utf-8') as f:
                self.config.write(f)
        except Exception as e:
            self.logger.error(f"Config saqlashda xatolik: {str(e)}")
    
    def is_token_expired(self) -> bool:
        """Token muddati tugaganligini tekshirish"""
        if not self.token_expires_at:
            return False
        return datetime.now() >= self.token_expires_at - timedelta(minutes=5)  # 5 minut oldin yangilash
    
    def rate_limit(self) -> None:
        """Rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)
        self.last_request_time = time.time()
    
    def make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Rate limited va retry bilan so'rov yuborish"""
        for attempt in range(self.max_retries):
            try:
                self.rate_limit()
                
                # Default timeout
                if 'timeout' not in kwargs:
                    kwargs['timeout'] = 30
                
                response = self.session.request(method, url, **kwargs)
                
                # Rate limit handling
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', self.retry_delay))
                    self.logger.warning(f"Rate limit hit, waiting {retry_after} seconds")
                    time.sleep(retry_after)
                    continue
                
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    self.logger.error(f"So'rov {self.max_retries} marta amalga oshmadi: {str(e)}")
                    return None
                else:
                    self.logger.warning(f"So'rov xatolik (urinish {attempt + 1}): {str(e)}")
                    time.sleep(self.retry_delay * (attempt + 1))
        
        return None
    
    def get_hh_authorization_url(self) -> str:
        """HeadHunter uchun authorization URL olish"""
        params = {
            'response_type': 'code',
            'client_id': self.hh_client_id,
            'redirect_uri': self.hh_redirect_uri,
            'scope': 'employer_vacancies employer_negotiations'
        }
        
        auth_url = f"{self.hh_oauth_base}/oauth/authorize?" + urlencode(params)
        return auth_url
    
    def get_access_token(self, authorization_code: str) -> Optional[str]:
        """Authorization code orqali access token olish"""
        token_url = f"{self.hh_oauth_base}/oauth/token"
        
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.hh_client_id,
            'client_secret': self.hh_client_secret,
            'code': authorization_code,
            'redirect_uri': self.hh_redirect_uri
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        try:
            self.logger.info(f"Token so'rovi yuborilmoqda: {token_url}")
            response = self.make_request('POST', token_url, data=data, headers=headers)
            
            if not response:
                return None
            
            self.logger.info(f"Token javob status: {response.status_code}")
            
            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get('access_token')
                refresh_token = token_data.get('refresh_token')
                expires_in = token_data.get('expires_in')
                
                if access_token:
                    self.save_token_to_config(access_token, refresh_token, expires_in)
                    self.hh_access_token = access_token
                    self.hh_refresh_token = refresh_token or ''
                    
                    success_msg = f"Yangi access token muvaffaqiyatli olindi (muddati: {expires_in}s)"
                    self.logger.info(success_msg)
                    self.send_telegram_log(success_msg)
                    return access_token
                else:
                    error_msg = f"Token javobida access_token yo'q: {token_data}"
                    self.logger.error(error_msg)
                    self.send_telegram_error({}, error_msg)
                    return None
            else:
                error_msg = f"Token olishda xatolik: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                self.send_telegram_error({}, error_msg)
                return None
                
        except Exception as e:
            error_msg = f"Token API ga murojaat qilishda xatolik: {str(e)}"
            self.logger.error(error_msg)
            self.send_telegram_error({}, error_msg)
            return None
    
    def refresh_access_token(self) -> bool:
        """Refresh token orqali yangi access token olish"""
        if not self.hh_refresh_token:
            self.logger.error("Refresh token mavjud emas!")
            return False
        
        token_url = f"{self.hh_oauth_base}/oauth/token"
        
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.hh_refresh_token,
            'client_id': self.hh_client_id,
            'client_secret': self.hh_client_secret
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        try:
            self.logger.info("Refresh token orqali yangi token olinmoqda...")
            response = self.make_request('POST', token_url, data=data, headers=headers)
            
            if not response:
                return False
            
            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get('access_token')
                refresh_token = token_data.get('refresh_token')
                expires_in = token_data.get('expires_in')
                
                if access_token:
                    self.save_token_to_config(access_token, refresh_token, expires_in)
                    self.hh_access_token = access_token
                    if refresh_token:
                        self.hh_refresh_token = refresh_token
                    
                    success_msg = f"Token muvaffaqiyatli yangilandi (muddati: {expires_in}s)"
                    self.logger.info(success_msg)
                    self.send_telegram_log(success_msg)
                    return True
                    
            error_msg = f"Token yangilashda xatolik: {response.status_code} - {response.text}"
            self.logger.error(error_msg)
            self.send_telegram_error({}, error_msg)
            return False
            
        except Exception as e:
            error_msg = f"Token yangilashda xatolik: {str(e)}"
            self.logger.error(error_msg)
            self.send_telegram_error({}, error_msg)
            return False
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Authentication headers olish"""
        # Token muddatini tekshirish va yangilash
        if self.is_token_expired():
            if not self.refresh_access_token():
                raise Exception("Token muddati tugagan va yangilab bo'lmayapti")
        
        return {
            'Authorization': f'Bearer {self.hh_access_token}',
            'Content-Type': 'application/json'
        }
    
    def test_api_access(self) -> Tuple[bool, str]:
        """API ga kirishni test qilish"""
        if not self.hh_access_token:
            return False, "Access token bo'sh yoki mavjud emas"
        
        try:
            headers = self.get_auth_headers()
            me_url = f"{self.hh_api_base}/me"
            self.logger.info(f"API test so'rovi: {me_url}")
            
            response = self.make_request('GET', me_url, headers=headers)
            
            if not response:
                return False, "API ga so'rov yuborib bo'lmadi"
            
            self.logger.info(f"API test javob status: {response.status_code}")
            
            if response.status_code == 200:
                user_data = response.json()
                is_employer = user_data.get('is_employer', False)
                email = user_data.get('email', 'N/A')
                
                if is_employer:
                    return True, f"Employer account tasdiqlandi: {email}"
                else:
                    return False, f"Bu account employer emas: {email}"
            elif response.status_code == 401:
                # Token yangilashga harakat
                if self.hh_refresh_token and self.refresh_access_token():
                    return self.test_api_access()  # Recursive call after refresh
                return False, "Access token yaroqsiz yoki muddati tugagan"
            elif response.status_code == 403:
                try:
                    error_data = response.json()
                    oauth_error = error_data.get('oauth_error', '')
                    description = error_data.get('description', '')
                    return False, f"Ruxsat yo'q: {description} (oauth_error: {oauth_error})"
                except:
                    return False, f"Ruxsat yo'q - tokenning scope'ini tekshiring: {response.text}"
            elif response.status_code == 404:
                return False, "API endpoint topilmadi - URL'ni tekshiring"
            else:
                return False, f"API xatolik: {response.status_code} - {response.text}"
                
        except Exception as e:
            return False, f"API test xatolik: {str(e)}"
    
    def get_hh_applications(self) -> List[Dict]:
        """HeadHunter dan oxirgi vakansiyalar va arizalarini olish"""
        if not self.hh_access_token:
            error_msg = "Access token mavjud emas!"
            self.logger.error(error_msg)
            self.send_telegram_error({}, error_msg)
            return []
        
        applications = []
        
        try:
            headers = self.get_auth_headers()
            
            # Employer ID olish
            me_url = f"{self.hh_api_base}/me"
            self.logger.info(f"Employer ID so'rovi yuborilmoqda: {me_url}")
            me_response = self.make_request('GET', me_url, headers=headers)
            
            if not me_response or me_response.status_code != 200:
                error_msg = f"Employer ID olishda xatolik: {me_response.status_code if me_response else 'No response'}"
                self.logger.error(error_msg)
                self.send_telegram_error({}, error_msg)
                return []
            
            employer_data = me_response.json()
            employer_id = employer_data.get('id')
            if not employer_id:
                error_msg = "Employer ID topilmadi!"
                self.logger.error(error_msg)
                self.send_telegram_error({}, error_msg)
                return []
            
            self.logger.info(f"Employer ID: {employer_id}")
            
            # Vakansiyalar olish
            vacancies_url = f"{self.hh_api_base}/vacancies"
            params = {
                'employer_id': employer_id,
                'per_page': 100,
                'page': 0
            }
            
            self.logger.info(f"Vakansiyalar so'rovi yuborilmoqda")
            vacancies_response = self.make_request('GET', vacancies_url, headers=headers, params=params)
            
            if not vacancies_response or vacancies_response.status_code != 200:
                error_msg = f"Vakansiyalarni olishda xatolik: {vacancies_response.status_code if vacancies_response else 'No response'}"
                self.logger.error(error_msg)
                self.send_telegram_error({}, error_msg)
                return []
            
            vacancies_data = vacancies_response.json()
            vacancies = vacancies_data.get('items', [])
            
            if not vacancies:
                info_msg = "Hozirda faol vakansiyalar topilmadi."
                self.logger.info(info_msg)
                return []
            
            self.logger.info(f"{len(vacancies)} ta vakansiya topildi")
            
            # Har bir vakansiya uchun arizalarni olish
            for vacancy in vacancies:
                vacancy_id = vacancy.get('id')
                vacancy_name = vacancy.get('name', 'Noma\'lum vakansiya')
                if not vacancy_id:
                    continue
                
                negotiations_url = f"{self.hh_api_base}/negotiations"
                params = {
                    'vacancy_id': vacancy_id,
                    'per_page': 100,
                    'page': 0
                }
                
                try:
                    negotiations_response = self.make_request('GET', negotiations_url, headers=headers, params=params)
                    
                    if negotiations_response and negotiations_response.status_code == 200:
                        negotiations_data = negotiations_response.json()
                        negotiations = negotiations_data.get('items', [])
                        
                        for negotiation in negotiations:
                            app_id = str(negotiation.get('id', ''))
                            if app_id and app_id not in self.processed_ids:
                                applications.append({
                                    'negotiation': negotiation,
                                    'vacancy_name': vacancy_name
                                })
                    else:
                        error_msg = f"Vakansiya {vacancy_id} uchun negotiations xatolik: {negotiations_response.status_code if negotiations_response else 'No response'}"
                        self.logger.warning(error_msg)
                
                except Exception as e:
                    error_msg = f"Vakansiya {vacancy_id} uchun xatolik: {str(e)}"
                    self.logger.warning(error_msg)
                    continue
            
            self.logger.info(f"HeadHunter dan {len(applications)} ta yangi ariza olindi")
            return applications
            
        except Exception as e:
            error_msg = f"HH API ga murojaat qilishda xatolik: {str(e)}"
            self.logger.error(error_msg)
            self.send_telegram_error({}, error_msg)
            return []
    
    def create_bitrix_lead(self, application_data: Dict) -> bool:
        """Bitrix24 ga lead yaratish"""
        try:
            negotiation = application_data.get('negotiation', {})
            vacancy_name = application_data.get('vacancy_name', 'Noma\'lum vakansiya')
            resume = negotiation.get('resume', {})
            
            first_name = resume.get('first_name', '')
            last_name = resume.get('last_name', '')
            
            email = ''
            phone = ''
            
            # Kontakt ma'lumotlarini olish
            if resume.get('contact'):
                contacts = resume['contact']
                if isinstance(contacts, list):
                    for contact in contacts:
                        contact_type = contact.get('type', {})
                        if isinstance(contact_type, dict):
                            if contact_type.get('id') == 'email':
                                email = contact.get('value', '')
                            elif contact_type.get('id') in ['cell', 'phone']:
                                phone = contact.get('value', '')
            
            # Lead ma'lumotlarini tayyorlash
            lead_data = {
                'fields': {
                    'NAME': first_name,
                    'LAST_NAME': last_name,
                    'EMAIL': [{'VALUE': email, 'VALUE_TYPE': 'WORK'}] if email else [],
                    'PHONE': [{'VALUE': phone, 'VALUE_TYPE': 'WORK'}] if phone else [],
                    'TITLE': vacancy_name,
                    'COMMENTS': self.format_comments(negotiation),
                    'SOURCE_ID': 'OTHER',
                    'SOURCE_DESCRIPTION': 'HeadHunter.uz',
                    'ASSIGNED_BY_ID': 1
                }
            }
            
            self.logger.info(f"Bitrix24 ga lead yuborilmoqda: {vacancy_name}")
            response = self.make_request('POST', self.bitrix_webhook, json=lead_data)
            
            if not response:
                self.logger.error("Bitrix24 ga so'rov yuborib bo'lmadi")
                self.send_telegram_error(lead_data['fields'], "Bitrix24 ga so'rov yuborib bo'lmadi")
                return False
            
            if response.status_code == 200:
                result = response.json()
                if result.get('result'):
                    lead_id = result['result']
                    self.logger.info(f"Lead yaratildi: ID {lead_id}")
                    self.send_telegram_success(lead_data['fields'], lead_id)
                    return True
                else:
                    error_msg = result.get('error_description', str(result.get('error', 'Noma\'lum xatolik')))
                    self.logger.error(f"Bitrix xatolik: {error_msg}")
                    self.send_telegram_error(lead_data['fields'], error_msg)
                    return False
            else:
                error_msg = f"Bitrix API xatolik: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                self.send_telegram_error(lead_data['fields'], error_msg)
                return False
                
        except Exception as e:
            error_msg = f"Lead yaratishda xatolik: {str(e)}"
            self.logger.error(error_msg)
            self.send_telegram_error({}, error_msg)
            return False
    
    def format_comments(self, negotiation: Dict) -> str:
        """Izohlarni formatlash"""
        resume = negotiation.get('resume', {})
        comments = []
        
        if resume.get('alternate_url'):
            comments.append(f"CV: {resume['alternate_url']}")
        
        if negotiation.get('created_at'):
            comments.append(f"Ariza vaqti: {negotiation['created_at']}")
        
        if resume.get('title'):
            comments.append(f"Kasb: {resume['title']}")
        
        if resume.get('age'):
            comments.append(f"Yoshi: {resume['age']}")
        
        if resume.get('area', {}).get('name'):
            comments.append(f"Joylashuv: {resume['area']['name']}")
        
        # Salary information
        if resume.get('salary'):
            salary = resume['salary']
            salary_from = salary.get('from')
            salary_to = salary.get('to')
            currency = salary.get('currency', 'UZS')
            
            salary_text = "Maosh: "
            if salary_from and salary_to:
                salary_text += f"{salary_from}-{salary_to} {currency}"
            elif salary_from:
                salary_text += f"dan {salary_from} {currency}"
            elif salary_to:
                salary_text += f"gacha {salary_to} {currency}"
            
            if salary_text != "Maosh: ":
                comments.append(salary_text)
        
        return '\n'.join(comments)
    
    def send_telegram_success(self, lead_data: Dict, lead_id: str) -> None:
        """Telegram ga muvaffaqiyatli xabar yuborish"""
        email_value = lead_data.get('EMAIL', [{}])[0].get('VALUE', 'N/A') if lead_data.get('EMAIL') else 'N/A'
        phone_value = lead_data.get('PHONE', [{}])[0].get('VALUE', 'N/A') if lead_data.get('PHONE') else 'N/A'
        
        message = (
            f"✅ <b>Yangi lead yaratildi!</b>\n\n"
            f"🆔 Lead ID: {lead_id}\n"
            f"👤 Ism: {lead_data.get('NAME', 'N/A')}\n"
            f"👤 Familiya: {lead_data.get('LAST_NAME', 'N/A')}\n"
            f"📞 Telefon: {phone_value}\n"
            f"📧 Email: {email_value}\n"
            f"💼 Lavozim: {lead_data.get('TITLE', 'N/A')}\n\n"
            f"🕐 Vaqt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🔗 Manba: HeadHunter.uz"
        )
        
        self.send_telegram_message(message)
    
    def send_telegram_error(self, lead_data: Dict, error: str) -> None:
        """Telegram ga xatolik xabarini yuborish"""
        message = (
            f"❌ <b>Xatolik yuz berdi!</b>\n\n"
            f"👤 Ism: {lead_data.get('NAME', 'N/A') if lead_data else 'N/A'}\n"
            f"👤 Familiya: {lead_data.get('LAST_NAME', 'N/A') if lead_data else 'N/A'}\n"
            f"🚫 Sabab: {error}\n\n"
            f"🕐 Vaqt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        self.send_telegram_message(message)
    
    def send_telegram_log(self, message: str) -> None:
        """Telegram ga log xabarini yuborish"""
        log_message = (
            f"📗 <b>Sistema Logi</b>\n\n"
            f"{message}\n\n"
            f"🕐 Vaqt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        self.send_telegram_message(log_message)
    
    def send_telegram_message(self, message: str) -> None:
        """Telegram ga xabar yuborish"""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = self.make_request('POST', url, json=data)
            
            if not response or response.status_code != 200:
                self.logger.error(f"Telegram xabar yuborishda xatolik: {response.status_code if response else 'No response'}")
                
        except Exception as e:
            self.logger.error(f"Telegram ga xabar yuborishda xatolik: {str(e)}")
    
    def process_applications(self) -> None:
        """Asosiy jarayon - arizalarni qayta ishlash"""
        try:
            self.logger.info("Arizalarni qayta ishlash boshlandi...")
            
            # API access tekshirish
            api_ok, api_message = self.test_api_access()
            if not api_ok:
                error_msg = f"API ga kira olmayapman: {api_message}"
                self.logger.error(error_msg)
                self.send_telegram_error({}, error_msg)
                return
            
            # Arizalarni olish
            applications = self.get_hh_applications()
            
            if not applications:
                self.logger.info("Yangi arizalar topilmadi")
                return
            
            processed_count = 0
            success_count = 0
            
            # Har bir arizani qayta ishlash
            for application in applications:
                try:
                    app_id = str(application['negotiation'].get('id', ''))
                    
                    if app_id in self.processed_ids:
                        continue
                    
                    if self.create_bitrix_lead(application):
                        success_count += 1
                    
                    self.save_processed_id(app_id)
                    processed_count += 1
                    
                    # Rate limiting
                    time.sleep(2)
                    
                except Exception as e:
                    error_msg = f"Arizani qayta ishlashda xatolik: {str(e)}"
                    self.logger.error(error_msg)
                    continue
            
            # Hisobot yuborish
            if processed_count > 0:
                summary_message = (
                    f"📊 <b>Qayta ishlash hisoboti</b>\n\n"
                    f"📥 Qayta ishlangan: {processed_count}\n"
                    f"✅ Muvaffaqiyatli: {success_count}\n"
                    f"❌ Xatolik: {processed_count - success_count}"
                )
                self.send_telegram_message(summary_message)
            
        except Exception as e:
            error_msg = f"Asosiy jarayonda xatolik: {str(e)}"
            self.logger.error(error_msg)
            self.send_telegram_error({}, error_msg)
    
    def cleanup_old_processed_ids(self, days_to_keep: int = 30) -> None:
        """Eski processed ID larni tozalash"""
        try:
            if not os.path.exists(self.processed_ids_file):
                return
            
            # Backup yaratish
            backup_file = f"{self.processed_ids_file}.backup.{datetime.now().strftime('%Y%m%d')}"
            if not os.path.exists(backup_file):
                with open(self.processed_ids_file, 'r') as src:
                    with open(backup_file, 'w') as dst:
                        dst.write(src.read())
            
            # Fayl o'lchamini tekshirish
            file_size = os.path.getsize(self.processed_ids_file)
            if file_size > 10 * 1024 * 1024:  # 10MB dan katta bo'lsa
                self.logger.info(f"Processed IDs fayli katta ({file_size/1024/1024:.1f}MB), tozalanmoqda...")
                
                # Oxirgi N ta ID ni saqlash
                with open(self.processed_ids_file, 'r') as f:
                    lines = f.readlines()
                
                # Oxirgi 10000 ta ID ni saqlash
                keep_lines = lines[-10000:] if len(lines) > 10000 else lines
                
                with open(self.processed_ids_file, 'w') as f:
                    f.writelines(keep_lines)
                
                # Memory dagi set ni yangilash
                self.processed_ids = set(line.strip() for line in keep_lines if line.strip())
                
                self.logger.info(f"Processed IDs fayli tozalandi, {len(keep_lines)} ta ID saqlandi")
        
        except Exception as e:
            self.logger.error(f"Processed IDs faylini tozalashda xatolik: {str(e)}")
    
    def health_check(self) -> Dict[str, any]:
        """Sistema holatini tekshirish"""
        status = {
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': (datetime.now() - self.start_time).total_seconds(),
            'processed_count': len(self.processed_ids),
            'token_valid': False,
            'token_expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None,
            'api_accessible': False,
            'bitrix_accessible': False
        }
        
        try:
            # Token tekshirish
            if self.hh_access_token:
                status['token_valid'] = True
                api_ok, api_message = self.test_api_access()
                status['api_accessible'] = api_ok
                status['api_message'] = api_message
            
            # Bitrix tekshirish (test lead yaratish)
            if self.bitrix_webhook:
                test_data = {'fields': {'TITLE': 'Health Check Test'}}
                response = self.make_request('POST', self.bitrix_webhook, json=test_data)
                status['bitrix_accessible'] = response is not None and response.status_code == 200
            
        except Exception as e:
            status['health_check_error'] = str(e)
        
        return status
    
    def start_scheduler(self) -> None:
        """Scheduler ni boshlash"""
        # Asosiy jarayon har 10 minutda
        schedule.every(10).minutes.do(self.process_applications)
        
        # Tozalash har kunda
        schedule.every().day.at("02:00").do(self.cleanup_old_processed_ids)
        
        # Health check har soatda
        schedule.every().hour.do(lambda: self.logger.info(f"Health check: {self.health_check()}"))
        
        start_message = (
            f"🚀 <b>HeadHunter-Bitrix24 tizimi ishga tushdi!</b>\n\n"
            f"⏰ Tekshirish intervali: har 10 minut\n"
            f"📅 Boshlash vaqti: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🔧 Versiya: 2.0 (yaxshilangan)"
        )
        
        self.send_telegram_message(start_message)
        
        # Dastlabki tekshirish
        self.process_applications()
        
        while True:
            try:
                schedule.run_pending()
                time.sleep(30)
            except KeyboardInterrupt:
                stop_message = "🛑 Tizim to'xtatildi"
                self.send_telegram_message(stop_message)
                self.logger.info(stop_message)
                break
            except Exception as e:
                error_msg = f"Scheduler xatolik: {str(e)}"
                self.logger.error(error_msg)
                self.send_telegram_error({}, error_msg)
                time.sleep(60)
        
        # Cleanup
        self.session.close()


def main():
    integration = HeadHunterBitrixIntegration()
    
    print(f"🔍 Config fayldagi access token: '{integration.hh_access_token[:20] if integration.hh_access_token else 'None'}...'")
    
    if not integration.hh_access_token:
        print("❌ HeadHunter access token mavjud emas yoki bo'sh!")
        print("🔗 Authorization URL:", integration.get_hh_authorization_url())
        print("\n📝 Qadamlar:")
        print("1. Yuqoridagi URL ga o'ting")
        print("2. HeadHunter account bilan login qiling")
        print("3. Ruxsat bering")
        print("4. Callback URL dan 'code' parametrini oling")
        print("5. Pastga code ni kiriting:")
        
        code = input("\nIltimos, authorization code ni kiriting: ").strip()
        if code:
            if integration.get_access_token(code):
                print("✅ Access token muvaffaqiyatli olindi!")
                print("🔄 Tizimni qayta ishga tushiring...")
            else:
                print("❌ Token olishda xatolik. Loglarni tekshiring.")
        else:
            print("❌ Code kiritilmadi!")
        return
    
    print("🔍 API access tekshirilmoqda...")
    api_ok, api_message = integration.test_api_access()
    
    if api_ok:
        print(f"✅ {api_message}")
        
        # Health check
        health = integration.health_check()
        print(f"📊 Sistema holati: {health}")
        
        print("🚀 Tizim ishga tushmoqda...")
        integration.start_scheduler()
    else:
        print(f"❌ {api_message}")
        if "yaroqsiz" in api_message or "muddati tugagan" in api_message:
            print("🔄 Refresh token bilan yangilanmoqda...")
            if integration.refresh_access_token():
                print("✅ Token yangilandi, qayta urinib ko'ring")
                main()  # Recursive call
            else:
                print("🔗 Yangi Authorization kerak:", integration.get_hh_authorization_url())
                print("Token muddati tugagan va yangilab bo'lmayapti. Yangi token oling.")


if __name__ == "__main__":
    main()
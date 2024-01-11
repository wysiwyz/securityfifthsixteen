# Spring Security 6 從略懂至很熟
註：本練習專案是跟著 Spring Security 6, 0 to Master along with JWT, OAUTH2 課程實作

1. 為何要用Spring Security
   - 困境：Application security is not fun and challenging to implement with our custom code/framework.
     - Spring Security 是由Spring其中一組熟悉security團隊考慮過所有security scenarios情況下，所打造的框架。使用Spring Security，能在最少的配置條件下，確保web apps的安全，不用再重造輪子
     - Spring Security 處理了常見資安弱點，像是CSRF與CORs。對於任何被識別的資安弱點，因為很多機構組織都使用Spring Security，它會立即的進行更新、補強弱點
     - 使用 Spring Security，可以用最簡單少量的配置，保證專案的pages/API路徑、enforce roles、方法level security
     - Spring Security支援眾多security標準來實作驗證機制，例如username/password驗證、JWT tokens、OAuth2、OpenID等等
2. Spring Security 內部流程 / 架構
   ![Internal_Flow](src/main/resources/static/images/spring_security_internal_flow.png)
   1. User用credential發送請求
      - **Spring Security Filters** 決定是否要對 userRequest 實施驗證
   2. Spring Security Filter extract username and password into Authentication object. 用戶名以及密碼會被抽出封裝成Authentication物件
      - Authentication是Spring Security code standard
   3. Spring Security Filters將userRequest轉交給 AuthenticationManager 
   4. AuthenticationManager如其名，負責管理驗證邏輯，確認這個請求要用LDAP Server、Database、Authentication Server或者Cache等各種驗證提供者
      - 如果請求送給各驗證提供者都失敗，AuthenticationManager則負責告知user failed request
   5. Authentication Providers 有很多種，可以直接寫驗證邏輯，或者可以 leverage spring security provider interface into classes which are UserDetailsManager and UserDetailsService
   6. Password Encoder 給密碼加密
   7. AuthenticationProvider完成之後，傳回 AuthenticationManager
   8. AuthenticationManager再傳回SpringSecurityFilters
   9. SpringSecurityFilter將結果傳給end user之前，會先將那筆Authentication物件存進SecurityContext
      - 包含驗證是否成功、是否有sessionId等等
   10. 最終資料傳回end user
3. Servlets 與 Filters
   - ★ 一個web app內典型的情境
     - 在Java web app中，Servlet Container(web server)負責替Java程式翻譯HTTP訊息。其中最常用的servlet container為Apache Tomcat。 
     - Servlet Container將HTTP訊息轉換成ServletRequest，並將其作為參數遞給Servlet方法。
     - 同樣的，ServletResponse會從Servlet輸出到Servlet Container，所以Java web app裡面寫的程式都是由Servlet驅動
   - ★ Filter 過濾器的角色
     - Java web app裡的Filter用來攔截每個request/response，也負責商業邏輯執行前的事前作業
     - 使用相同的過濾器，Spring Security可以透過配置設定強化web app security
   > 翻成白話文就是：web/app server 裡面有一些filters和servlets，client客戶發送請求進AppServer，到達servlet之前，都會經過filters
4. 內部流程相關名詞解釋
   - Spring Security Filters: 是一系列的過濾器，用以攔截每個請求，會協同確認這一筆請求是否需要Authentication。如果需要，就會將user導至login頁面，或使用一開始儲存在authentication的既有details
   - `Authentication`: 例如 UsernamePasswordAuthenticationFilter 的過濾器會從http請求中提取username/password，並製作Authentication物件。
      Authentication此物件是Spring Security框架中，儲存已驗證的user details的核心標準
   - `AuthenticationManager`: 從過濾器接收到請求後，將user detail的驗證工作分配給可用的驗證提供者。一個app可能有多個提供者，
      會由AuthenticationManager管理
   - `AuthenticationProvider`: 所有驗證user的核心邏輯
   - `UserDetailsManager/UserDetailsService`: 協助取得、建立、更新、刪除資料庫或儲存系統中的userDetails
   - `PasswordEncoder`: 加密與哈希密碼的服務介面
   - `SecurityContext`: 一旦請求被驗證了，Authentication物件會被存放在執行緒區域(thread-local)的SecurityContext，
      這個物件由SecurityContextHolder管理，有助於驗證這個user之後發送的請求

### Ready to go through the filters? Go!
Spring Security Filters 有很多個，以下列出幾個較為重要的過濾器：
(Roles: helps to perform authentication, authorization, displaying the login page, storing the authentication details, etc.)
1. `AuthorizationFilter.java` 確認該url是否為公開或需要驗證授權的連結
2. `DefaultLoginPageGeneratingFilter.java` 如果user試圖存取securedURL，就會進入此過濾器，顯示給user看的預設登入頁
3. `UsernamePasswordAuthenticationFilter.java` 在user輸入帳密等credential後，會進入此過濾器
   - `attemptAuthention()`方法會建立Authentication物件
   - `UsernamePasswordAuthenticationToken.java` 為什麼要建立此？它實作了Authentication介面
   - 再藉由`ProviderManager`物件使上述的AuthenticationToken生效，這個ProviderManager實作了AuthenticationManager介面
   - 這個Manager裡的authenticate()方法會遍歷所有authenticationProviders，如果同時有兩個有效providers，其中一個先驗證成功，
     就不會執行第二個驗證，如果第一個驗證失敗了，就會繼續試第二個驗證

> pending question: 那要如何規範哪些頁面需要login，哪些不用？

### Sequence Flow - Spring Security預設行為
![Sequential_Flow](src/main/resources/static/images/spring_security_sequential_flow.png)
1. User trying to access a secure page for the first time.
2. Behind the scenes few filters like `AuthorizationFilter`, `DefaultLoginPageGeneratingFilter` identify that the user is not logged in & redirect the user to login page.
3. User entered his credentials and the request is intercepted by filters.
4. Filters like `UsernamePasswordAuthenticationFilter`, extracts the username, password from the request and form an object of `UsernamePasswordAuthenticationToken` which is an implementation of Authentication interface. With the object created it invokes `authenticate()` method of `ProviderManager`.
5. `ProviderManager` which is an implementataion of `AuthenticationManager` identify the list of Authentication providers available that are supporting given authentication object style. In the default behavior, `authenticate()` method of `DaoAuthenticationProvider` will be invoked by `ProviderManager`.
6. `DaoAuthenticationProvider` invokes the method `loadUserByUsername()` of `InMemoryUserDetailsManager` to load the user details from memory. Once the user details loaded, it takes help from the default password encoder implementation to compare the password and validate if the user is authenticated or not.
7. At last it returns the `Authentication` object with the details of authentication success or not to `ProviderManager`.
8. ProviderManager checks if authentication is successful or not. If not, it will try with other available AuthenticationProviders. Otherwise, it simply returns the authentication details to the filters.
9. The Authentication object is stored in the SecurityContext object by the filter for future use and the response will be returned to the end user.
![Simplified_sequential_flow](src/main/resources/static/images/spring_security_sequential_flow_simplified.png)

- 當user發送多筆請求，Spring Security為什麼都不會跟他要credentials?
  - Storage -> Cookies (this url) -> Name: JSESSIONID。這個JSESSIONID以cookie形式儲存在瀏覽器browser裡面，這個cookie在之後的每個請求，也會被瀏覽器傳送給後端伺服器，

## 02-001 此package的backend REST services
- 不需要驗證授權的服務
  - `/contact`: 從『聯絡我們』頁面接收資料，存進DB
  - `/notices`：從資料庫傳送公告通知到『公吿消息』頁面
- 有security需求服務
  - `/myAccount`：將登入user的『帳戶明細』從DB傳至UI
  - `/myBalance`：將登入user的『餘額與交易明細』從DB傳至UI
  - `/myLoans`：將登入user的『貸款明細』從DB傳至UI
  - `/myCards`：將登入user的『信用卡明細』從DB傳至UI

- By default, Spring Security framework will try to secure all the services that you have inside our web application.

## 02-005 
- Spring Security預設會讓專案內所有路徑都受到保護 (需要credentials)，原因是出自於`SpringBootWebSecurityConfiguration`類別中的
`defaultSecurityFilterChain(HttpSecurity http)`方法
- 如果user指定他們自定義的SecurityFilterChain bean，這個類別就會完全停用
```java
static class SpringBootWebSecurityConfiguration {
    // ...
    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //any request that is coming towards my app has to be authenticated⬇️
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        //the request can come through a html form or from rest-api application or postman application
        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build(); 
    }
    // ...
}
```

## 02-008
有時候客戶端會提一些奇怪需求，例如拒絕所有發送到app的api請求，使用SpringSecurity框架達成的話，如下程式
即便user輸入了帳號密碼，仍然只會收到 403 錯誤（通過驗證了，但並未授權）
even though your authentication is successful, but authorization is still denied. 

```java
@Configuration
public class ProjectSecurityConfig {
    /**
     * Configuration to deny all the requests
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .anyRequest().denyAll()
                .and().formLogin()
                .and().httpBasic();
        return http.build();
    }
}
```

## 02-009
相對於上個情境，也會有允許所有請求的狀況（常見）
```java
@Configuration
public class ProjectSecurityConfig {
    /**
     * Configuration to permit all the requests
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .anyRequest().permitAll()
                .and().formLogin()
                .and().httpBasic();
        return http.build();
    }
}
```

## 03-001
只有一個 user 哪夠？
如何將user credentials存進資料庫，再用db驗證

## 03-002
建立多個users---Approach 1
- 使用 InMemoryUserDetailsManager
- 不適合用於生產/正式環境
- 使用 `withDefaultPasswordEncoder()`(deprecated)
- 方法標註`@Bean`表示此方法回傳的物件會被轉換成一個bean
```java
@Configuration
public class ProjectSecurityConfig {
    // ...
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("99999")
                .authorities("admin")
                .build();
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("88888")
                .authorities("read")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
    }
}
```

## 03-003
建立多個users---Approach 2
- 分別建立PasswordEncoder的bean
- 使用NoOpPasswordEncoder的實例
- 密碼未加密，也不適合production環境
```java
@Configuration
public class ProjectSecurityConfig {
    // ...
    /**
     * Approach 2: where we use NoOpPasswordEncoder Bean while creating user details
     * @return InMemoryUserDetailsManager
     */
     @Bean
     public InMemoryUserDetailsManager userDetailsService() {
         UserDetails admin = User.withUsername("admin")
                 .password("99999")
                 .authorities("admin")
                 .build();
         UserDetails user = User.withUsername("user")
                 .password("88888")
                 .authorities("read")
                 .build();
         return new InMemoryUserDetailsManager(admin, user);
     }

     /**
      * Approach 2 is only for non-prod, as it treats password as plain text.
      * @return PasswordEncoder
      */
     @Bean
     public PasswordEncoder passwordEncoder() {
         return NoOpPasswordEncoder.getInstance();
     }
}
``` 
## 03-004
用戶管理相關的類別與介面
- `UserDetailsService` \[介面] 核心介面，加載user特定的資料
  - `loadUserByUsername(String username)`
- `UserDetailsManager` \[介面] 繼承UserDetailsService，提供建立新users並更新既有users的功能
  - `createUser(UserDetails user)`
  - `updateUser(UserDetails user)`
  - `deleteUser(String username)`
  - `changePassword(String oldPwd, String newPwd)`
  - `userExists(String username)`
- Spring Security提供的實作類別
  - `InMemoryUserDetailsManager`
  - `JdbcUserDetailsManager`
  - `LdapUserDetailsManager`
上述這些介面與類別都使用了`UserDetails`介面，提供基本user資料
  - `User`實作了`UserDetails`

## 03-005
- 保障安全性的設計模式：User或UserDetails都沒有欄位的setter，即建構子注入欄位值之後就不可覆寫或更改
- Authentication與UserDetails之間的關聯
  - UserDetails介面與實作的User類別
    - 是當你要從儲存系統加載用戶資料時，會回傳的類型
    - 例：UserDetailsService與UserDetailsManager裡面的方法
    - 常用方法
      - getPassword()
      - getUsername()
      - getAuthorities()
      - isAccountNonExpired()
      - isAccountNonLocked()
      - isEnable()
      - isCredentialsNonExpired()
      - eraseCredential()
  - `Principal`介面、`Authentication`介面與`UsernamePasswordAuthenticationToken`類別
    - 是當你要決定驗證結果成功與否的情境中，會回傳的類型
    - 例：AuthenticationProvider與AuthenticationManager裡面的方法
    - 常用方法
      - getName()
      - getPrincial()
      - getAuthorities()
      - getCredentials()
      - getDetails()
      - isAuthenticated()
      - setAuthenticated()
      - eraseCredentials()
  
## 03-006
- `UserDetailsService`介面
  - 適用於加載特定用戶資料的情境
  - 方法 `loadUserByUsername(String username)`
- `UserDetailsManager`，繼承`UserDetailsService`的介面
  - 可以新增user或更新/刪除既有user
  - 方法 
    - `changePassword(String, String)`
    - `createUser(UserDetails)`
    - `deleteUser(String)`
    - `loadUserByUserNamd(String)`
    - `updateUser(UserDetails)`
    - `userExists(String)` 

## 03-007
Spring Security提供的三個實作類別
1. InMemoryUserDetailsManager
   - 當建構了這一個物件，傳入的UserDetails(1~多筆)會被for-loop，每筆丟進`createUser(User)`方法
   - `createUser(UserDetails)`如果不是既有存在的username，則會將這筆userDetail存進map(k:username小寫, v:MutableUser物件)
2. JdbcUserDetailsManager
   - Q: 資料表結構為何？欄位名稱為何？要把userDetails存在哪？A: Spring Security有預設一個DB結構、table結構、欄位名稱
   - `JdbcDaoImpl` - select username, password, enabled from users where username = ?
     - 資料表名稱預設為users，相關資料在 users.ddl 裡面
     - 除了users對應authorities，也可以使用`GroupManager`建立群組，並將user分配進所屬群組
3. LdapUserDetailsManager
   - 要先加入兩個依賴 `spring-security-ldap` & `spring-ldap-core`
   - 不是很常用，除非專案有用到Ldap儲存用戶訊息

## 03-008
MySQL cloud server
- 可以用 AWS amazon free tier 建立
  - RDS如果stop temporarily要一週後才能重啟（希望沒有聽錯）
  - 趕快做完實作，趕緊刪庫，以免扣錢
- 使用連結 [Free MySQL Hosting](https://www.freemysqlhosting.net/)
  - 不會跟你要信用卡號碼
  - 但每週都會寄信確認你還有沒有在使用
  - 不確定何時會中止免費服務

## 03-009
[SQL Ectron](https://sqlectron.github.io/)
- 輸入先前在AWS建立資料庫的User帳號名稱 `admin` 與密碼
- Database type選這專案要使用的MySQL
- Server Address Host貼上AWS>RDS>springsecurity>Connectivity & security>Endpoint & port的Endpoint
- 建立資料庫 newIBank
- 執行Security JAR檔案的 users.ddl➡️fail
- 使用Security官方文檔案的 [JDBC_users schema](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/jdbc.html) ➡️fail
- 加入一筆用戶happy
- 相關ddl放在 resources/sql 路徑之下 (scripts.sql)

## 03-010
- 因為要實作JdbcUserDetailsManager，故須增加三個dependencies
  - spring boot starter jdbc 資料庫連線
  - my sql connector-j 要連接的資料庫
    - scope 設定 runtime
  - spring boot starter data jpa 執行資料庫相關交易
- load maven changes (Intellij mac 快捷鍵：`shift⇧` + `command⌘` + `I`)
- 在application.properties設定檔案加入配置
- ProjectSecurityConfig中，與InMemoryUserDetailsManager相關的方法，註解之
- ProjectSecurityConfig 加入以下方法
  ```java
  public class ProjectSecurityConfig {
      //...
      @Bean
      public UserDetailsService userDetailsService(DataSource dataSource) {
          return new JdbcUserDetailsManager(dataSource);
      }
  }
  ```
  - 為何回傳物件可以這樣寫？因為JdbcUserDetailsManager實作了UserDetailsManager介面，而此介面繼承了UserDetailsService介面
- 上一個approach其中一個方法建立的PasswordEncoder仍要保留，為何？
  - You should always communicate to spring security how our passwords are stored. Whether they are stored in plain text password or hashing/encryption.
- 後續會示範如何store password in encrypted format

## 03-011
建立自定義的 users table (客戶說：我想透過email驗證,要增加email欄位, 我想要用更符合我司習慣的欄位命名)
- 這樣的情況就不能用JdbcUserDetailsManager了，要自己實作`UserDetailsService`以及`UserDetailsManager`
- 首先建立一個 customer 資料表 (參考本專案 scripts.sql)，其它下回分曉

## 03-012
- 建立package`model`，裡面新建class`Customer`，類別加上標註`@Entity`
  - `@Entity`:
    - 是 spring data jpa 框架的標註型別
      - 指的是要被建立的該類別，即代表database其中一張資料表
  - `@Id`: act as a primary key
  - `@GeneratedValue(strategy=GenerationType.AUTO)`
    - no need to provide manually, instead, the framework will work with the database server 
      and automatically generate the next id value that is available inside the database
- 建立package`repository`，裡面新建class`CustomerRepository`
  - 繼承自 JpaRepository<T, type of the field per T that is annotated with @Id> 
  - 此介面以`@Repository`標註
- 如果這兩個 java class 是建立在 main package (newibankbackend) 以外的地方，要在程式入口點main()所在的類別加上兩個標註：
  - `@EntityScan("com.march.nibbackend.model")`
  - `@EnableJpaRepositories("com.march.nibbackend.repository")`
  - 用以要求Spring去掃描這些類別並建立beans，供後續商業邏輯使用
- 另外在主程式類別上面掛標註`@EnableWebSecurity`
  - 如果你建立的SpringSecurity的專案，就不必掛這個annotation
  - 適用在專案沒有spring-security dependency的情況

## 03-013
接下來要用自定義的table建立對應的UserDetailsManager
- 要實作 UserDetailsService 介面，覆寫`loadUserByUsername()`方法，回傳UserDetails
- 在config package底下，新建類別`NewIBankUserDetails`，實作 UserDetailsService 介面
  - GrantedAuthority: interface from java library
  - SimpleGrantedAuthority: class from spring security
  - 這類別要加上`@Service`標註，才能creating this class as a bean
  - 目前產生兩個實作UserDetailsService的bean，會使DaoAuthenticationProvider混淆
    - `No AuthenticationProvider found for ...UsernamePasswordAuthenticationToken`
    - 解：先註解 ProjectSecurityConfig 產生 UserDetailsService bean 的方法
    - 這樣就能順利使用 customer 表裡面的 user 登入了
    ```java
    @Service
    public class NewIBankUserDetails implements UserDetailsService {

      @Autowired
      CustomerRepository customerRepository;

      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String userName = null;
        String password = null;
        List<GrantedAuthority> authorities =  new ArrayList<>();
        List<Customer> customer = customerRepository.findByEmail(username);
        if (customer.isEmpty()) {
            throw new UsernameNotFoundException("User details not found for the user: " + username);
        } else {
            userName = customer.get(0).getEmail();
            password = customer.get(0).getPwd();
            authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
        }
        return new User(username, password, authorities);
      }
    }
    ```
    
## 03-014
註冊新用戶---新增一支REST API
- 有兩種方式達成 (1) 實作UserDetailsManager; (2) 修改loadUserByUsername方法
- 建立一個`LoginController`，registerUser方法
- 先取消csrf，在ProjectSecurityConfig修改方法defaultSecurityFilterChain
- 修改 customer model 的 id欄位標註
  ```java
  @Entity
  public class Customer { 
      @Id
      @GeneratedValue(strategy = GenerationType.AUTO, generator = "native")
      @GenericGenerator(name="native", strategy="native")
      private Long id;
      //other fields
  }
  ```
- 再用postman測試註冊，註冊成功後就可以在UI登入
![postman](src/main/resources/static/images/register_postman.png)

## 04-001
- 預設的PasswordEncoder是如何驗證密碼的？
  - 純文字比對密碼會有機密問題，不適合正式環境
  - 實際可查看`DaoAuthenticationProvider`類別中的`additionalAuthenticationChecks`方法
  - `this.passwordEnoder`當前使用的是NoOpPasswordEncoder，`matches(CharSequence, String)`不夠secure

## 04-002
密碼管理的不同方式：比較Encoding, Encryption以及Hashing
- Encoding 編碼
  - 將資料從一種格式轉換(convert)為另一格式的程序，與加密學無關
  - 沒有秘密，完全可逆的
  - 編碼不能用來保障資料安全，不適用於密碼管理
  - 編碼常用演算法：ASCII, BASE64, UNICODE
- Encryption 加密
  - 改變(transform)資料內容的程序，可以保證機密性
  - 為了達成機密係，加密必須有一把鑰匙(key)
  - 可以用key逆向得到原本文的內容，只要key保有機密性，加密就能保障安全
- Hashing 哈希/雜湊演算法
  - 使用hashing函式將資料轉換為hash value
  - hashed資料不可逆，無法用產生的hash value推回原文
  - 如果給定一些原始資料與哈希後的對照組，就能驗證雜湊後的值是否與原始值匹配


## 04-004
- Bcrypt是雜湊演算法其中一種
- Rounds of hash預設是12
- 如果原始文本相同，hash rounds不變，每一次的bcrypt-hash encrypt結果還是會不同
- 登入時：Hash to check 就會是存在DB的文本，比對 String to check against 用戶輸入的密碼
[Bcrypt-online generator](https://bcrypt-generator.com/)
- Given some arbitrary data along with the output of a hashing algorithm, one can verify whether this data matches the original input data without needing to see the original data.

## 04-005
PasswordEncoder interface
- PasswordEncoder介面有三個方法
  ```java
  public interface PasswordEncoder {
    String encode(CharSequence rawPassword);
    boolean matches(CharSequence rawPassword, String encodedPassword);
    // 密碼是否要再加密一次
    default boolean upgradeEncoding(String encodedPassword) {
      return false;
    }
  }
  ```
- PasswordEncoder介面的不同實作類別
  - `NoOpPasswordEncoder` (not for prod)
  - `StandardPasswordEncoder` (not for prod)
  - `Pbkdf2PasswordEncoder`
  - `BCryptPasswordEncoder`
  - `SCryptPasswordEncoder`
  - `Argon2PasswordEncoder`

## 04-006
PasswordEncoder 的實作類別
- `NoOpPasswordEncoder` (not for prod)
  - 純文字比對，存進資料表之前不加密
- `StandardPasswordEncoder` (not for prod)
  - Deprecated class
  - 只用來支援舊系統(for legacy purpose)
- `Pbkdf2PasswordEncoder`
  - 一樣不建議用於正式環境
  - 5~6年前還算secured，但現在GPU brute force attack緣故，變成中等強度了

#### Brute force attack是什麼
假設一個駭客取得了驗證用的資料表，有其中一兩個user使用了弱強度的密碼，
他就能很快猜出對應的原始文本。可能會寫一個程式，會一直傳進最常用的密碼，
以及最常用的字典詞彙，不對就繼續餵常用密碼，會需要很多processing與memory性能，
開發人員有兩種方法可以 delay hacking logic:
(1) 教育end user不要使用簡單的密碼，在輸入欄位驗證大小寫/符號/英數字
(3) 使用比較強的hashing algorithm，例如BCrypt或SCrypt

## 04-007
PasswordEncoder 的實作類別
- `BCryptPasswordEncoder`
  - B-crypt hashing algorithm, invented in 1999
  - demand computations power(GPU/CPU) from hacker mission
  - the most common application
- `SCryptPasswordEncoder`
  - C-crypt is advanced version of B-crypt password encoder
  - demand two parameters: computation power, memory allocation(RAM)
- `Argon2PasswordEncoder`
  - Even more latest algo
  - three dimension parameters: computation power, memory, multiple threads
  - but it also takes longer time for your web app to hash during login time

## 04-008
Demo: BCryptPasswordEncoder, new user registration
- 首先在 ProjectSecurityConfig 建立 PasswordEncoder 的地方，改為回傳 `new BcryptPasswordEncoder()`
- 接著，LoginController 的`registerUser()`方法中加入 `passwordEncoder.encode(String)`，存進Customer物件再存入table

## 04-009
Demo: BCryptPasswordEncoder, user login
- Pattern: 首字母 $2a或$2y或$2b(三種version)
- BCryptPasswordEncoder建構子：可以設定 version, secureRandom(salt加鹽), strength(log rounds雜湊幾次), 或者都用預設的
  - version: $2a或$2y或$2b，預設為$2a
  - strength (workload factor/log rounds): 最低4次，最高31次，預設為10次
  - secure random value: 隨機產生的數值，用來讓hacker mission更加崎嶇
- `BCrypt.checkpw(rawPwd, encodedPwd)`方法:
  1. The rawPwd will be hashed in the same strength, same version
  2. It's going to check the hash value is the same for the two hash strings. 
- 如果使用了先前 NoOpPasswordEncoder 存進 table 的 user 資料登入，會`log.warn("Encoded password does not look like BCrypt");`

> pending question: 那AESxRSA的PasswordEncoder是怎麼實作的？


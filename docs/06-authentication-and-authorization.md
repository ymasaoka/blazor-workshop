# Authentication

The application is working well. Users can place orders and track their order status. But there's one little problem: currently we don't distinguish between users at all. The "My orders" page lists *all* orders placed by *all* users, and anybody can view the state of anybody else's order. Your customers, and privacy regulations, may have an issue with this.

The solution is *authentication*. We need a way for users to log in, so we know who's who. Then we can implement *authorization*, which is to enforce rules about who's allowed to do what.

## Enforcement is on the server

The first and most important principle is that all *real* security rules must be enforced on the backend server. The client (UI) merely shows or hides options as a courtesy to well-behaved users, but a malicious user can always change the behavior of the client-side code.

As such, we're going to start by enforcing some access rules in the backend server, even before the client code knows about them.

Inside the `BlazorPizza.Server` project, you'll find `OrdersController.cs`. This is the controller class that handles incoming HTTP requests for `/orders` and `/orders/{orderId}`. To require that all requests to these endpoints come from authenticated users (i.e., people who have logged in), add the `[Authorize]` attribute to the `OrdersController` class:

```csharp
[Route("orders")]
[ApiController]
[Authorize]
public class OrdersController : Controller
{
}
```

The `AuthorizeAttribute` class is located in the `Microsoft.AspNetCore.Authorization` namespace.

If you try to run your application now, you'll find that you can no longer place orders, nor can you retrieve details of orders already placed. Requests to these endpoints will return HTTP 302 redirects to a login URL that doesn't exist. That's good, because it shows that rules are being enforced on the server!

![Secure orders](https://user-images.githubusercontent.com/1874516/77242788-a9ce0c00-6bbf-11ea-98e6-c92e8f7c5cfe.png)

## Tracking authentication state

The client code needs a way to track whether the user is logged in, and if so *which* user is logged in, so it can influence how the UI behaves. Blazor has a built-in DI service for doing this: the `AuthenticationStateProvider`. Blazor provides an implementation of the `AuthenticationStateProvider` service and other related services and components based on [OpenID Connect](https://openid.net/connect/) that handle all the details of establishing who the user is. These services and components are provided in the Microsoft.AspNetCore.Components.WebAssembly.Authentication package, which has already been added to the client project for you.

In broad terms, the authentication process implemented by these services looks like this:

* When a user attempts to login or tries to access a protected resource, the user is redirected to the app's login page (`/authentication/login`).
* In the login page, the app prepares to redirect to the authorization endpoint of the configured identity provider. The endpoint is responsible for determining whether the user is authenticated and for issuing one or more tokens in response. The app provides a login callback to receive the authentication response.
  * If the user isn't authenticated, the user is first redirected to the underlying authentication system (typically ASP.NET Core Identity).
  * Once the user is authenticated, the authorization endpoint generates the appropriate tokens and redirects the browser back to the login callback endpoint (`/authentication/login-callback`).
* When the Blazor WebAssembly app loads the login callback endpoint (`/authentication/login-callback`), the authentication response is processed.
  * If the authentication process completes successfully, the user is authenticated and optionally sent back to the original protected URL that the user requested.
  * If the authentication process fails for any reason, the user is sent to the login failed page (`/authentication/login-failed`), and an error is displayed.

See also [Secure ASP.NET Core Blazor WebAssembly](https://docs.microsoft.com/aspnet/core/security/blazor/webassembly/) for additional details.

To enable the authentication services, add a call to `AddApiAuthorization` in *Program.cs* in the client project:

```csharp
public static async Task Main(string[] args)
{
    var builder = WebAssemblyHostBuilder.CreateDefault(args);
    builder.RootComponents.Add<App>("app");

    builder.Services.AddBaseAddressHttpClient();
    builder.Services.AddScoped<OrderState>();

    // Add auth services
    builder.Services.AddApiAuthorization();

    await builder.Build().RunAsync();
}
```

Also add the following `script` tag in *index.html* after the `script` tag for *blazor.webassembly.js*:

```html
<script src="_content/Microsoft.AspNetCore.Components.WebAssembly.Authentication/AuthenticationService.js"></script>
```

The added services will be configured by default to use an identity provider on the same origin as the app. The server project for the Blazing Pizza app has already been setup to use [IdentityServer](https://identityserver.io/) as the identity provider and ASP.NET Core Identity for the authentication system:

*Startup.cs*

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddMvc()
        .AddNewtonsoftJson();

    services.AddDbContext<PizzaStoreContext>(options => 
        options.UseSqlite("Data Source=pizza.db"));

    services.AddDefaultIdentity<PizzaStoreUser>(options => options.SignIn.RequireConfirmedAccount = true)
        .AddEntityFrameworkStores<PizzaStoreContext>();

    services.AddIdentityServer()
        .AddApiAuthorization<PizzaStoreUser, PizzaStoreContext>();

    services.AddAuthentication()
        .AddIdentityServerJwt();
}
```

The server has also already been configured to issue tokens to the client app:

*appsettings.json*

```json
"IdentityServer": {
  "Clients": {
    "BlazingPizza.Client": {
      "Profile": "IdentityServerSPA"
    }
  }
}
```

To orchestrate the authentication flow, add an `Authentication` component to the *Pages* directory in the client project:

*Pages/Authentication.razor*

```razor
@page "/authentication/{action}"
@using Microsoft.AspNetCore.Components.WebAssembly.Authentication
<RemoteAuthenticatorView Action="@Action" />

@code{
    [Parameter]
    public string Action { get; set; }
}
```

The `Authentication` component is setup to handle the various authentication actions using the built-in `RemoteAuthenticatorView` component. The `Action` parameter is bound to the `{action}` route value, which is then passed to the `RemoteAuthenticatorView` component to handle.

To flow the authentication state information through your app, you need to add one more component. In `App.razor`, surround the entire `<Router>` with a `<CascadingAuthenticationState>`:

```html
<CascadingAuthenticationState>
    <Router AppAssembly="typeof(Program).Assembly" Context="routeData">
        ...
    </Router>
</CascadingAuthenticationState>
```

At first this will appear to do nothing, but in fact this has made available a *cascading parameter* to all descendant components. A cascading parameter is a parameter that isn't passed down just one level in the hierarchy, but through any number of levels.

Finally, you're ready to display something in the UI!

## Displaying login state

Create a new component called `LoginDisplay` in the client project's `Shared` folder, containing:

```html
@inject NavigationManager Navigation
@inject SignOutSessionStateManager SignOutManager

<div class="user-info">
    <AuthorizeView>
        <Authorizing>
            <text>...</text>
        </Authorizing>
        <Authorized>
            <img src="img/user.svg" />
            <div>
                <a href="authentication/profile" class="username">@context.User.Identity.Name</a>
                <button class="btn btn-link sign-out" @onclick="BeginSignOut">Sign out</button>
            </div>
        </Authorized>
        <NotAuthorized>
            <a class="sign-in" href="authentication/register">Register</a>
            <a class="sign-in" href="authentication/login">Log in</a>
        </NotAuthorized>
    </AuthorizeView>
</div>

@code{
    async Task BeginSignOut()
    {
        await SignOutManager.SetSignOutState();
        Navigation.NavigateTo("authentication/logout");
    }
}
```

`<AuthorizeView>` is a built-in component that displays different content depending on whether the user meets specified authorization conditions. We didn't specify any authorization conditions, so by default it considers the user authorized if they are authenticated (logged in), otherwise not authorized.

You can use `<AuthorizeView>` anywhere you need UI content to vary by authorization state, such as controlling the visibility of menu entries based on a user's roles. In this case, we're using it to tell the user who they are, and conditionally show either a "log in" or "log out" link as applicable.

The links to register, log in, and see the user profile are normal links that navigate to the `Authentication` component. The sign out link is a button and has additional logic to prevent forged request logging the user out. Using a button ensures that the sign out can only be triggered by a user action, and the `SignOutSessionStateManager` service maintains state across the sign out flow to ensure the whole flow originated with a user action.

Let's put the `LoginDisplay` in the UI somewhere. Open `MainLayout`, and update the `<div class="top-bar">` as follows:

```html
<div class="top-bar">
    (... leave existing content in place ...)

    <LoginDisplay />
</div>
```

## Register a user and log in

Try it out now.


## Ensuring authentication before placing an order

If you're now logged in, you'll be able to place orders and see order status. But if you log out then make another attempt to place an order, bad things will happen. The server will reject the `POST` request, causing a client-side exception, but the user won't know why.

To fix this, let's make the UI prompt the user to log in (if necessary) as part of placing an order.

In the `Checkout` page component, add an `OnInitializedAsync` with some logic to to check whether the user is currently authenticated. If they aren't, send them off to the login endpoint.

```cs
@code {
    [CascadingParameter] public Task<AuthenticationState> AuthenticationStateTask { get; set; }

    protected override async Task OnInitializedAsync()
    {
        var authState = await AuthenticationStateTask;
        if (!authState.User.Identity.IsAuthenticated)
        {
            // The server won't accept orders from unauthenticated users, so avoid
            // an error by making them log in at this point
            NavigationManager.NavigateTo("user/signin?redirectUri=/checkout", true);
        }
    }

    // Leave PlaceOrder unchanged here
}
```

Try it out: now if you're logged out and get to the checkout screen, you'll be redirected to log in. The value for the `[CascadingParameter]` comes from your `AuthenticationStateProvider` via the `<CascadingAuthenticationState>` you added earlier.

But do you notice something a bit awkward about it? It still shows the checkout UI briefly before the browser loads the Twitter login page. We can fix that easily by wrapping the "checkout" UI inside an `<AuthorizeView>`. Update the markup in `Checkout.razor` as follows:

```html
<div class="main">
    <AuthorizeView Context="authContext">
        <NotAuthorized>
            <h2>Redirecting you...</h2>
        </NotAuthorized>
        <Authorized>
            [the whole EditForm and contents remains here]
        </Authorized>
    </AuthorizeView>
</div>
```

That's better! Now you don't get the awkward brief appearance of a non-applicable bit of UI, and you can't possibly click the *Place order* button really quickly before the redirection completes.

## Preserving order state across the redirection flow

We've just introduced a pretty serious defect into the application. Since you're building a client-side SPA, the application state (such as the current order) is held in the browser's memory. When you redirect away to log in, that state is discarded. When the user is redirected back, their order has now become empty!

Check you can reproduce this bug. Start logged out, and build an order. Then go to the checkout screen via the redirection. When you get back to the app, you should be able to see your order contents were lost. This is a common concern with browser-based single-page applications (SPAs), but fortunately there are straightforward solutions.

We'll fix the bug by persisting the order state in the browser's `localStorage`. Since `localStorage` is a JavaScript API, we can reach it using *JavaScript interop*. Go back to `Checkout.razor` and at the top, inject an instance of `IJSRuntime`:

```cs
@inject IJSRuntime JSRuntime
```

Then, inside `OnInitializedAsync`, add the following line just above the `NavigationManager.NavigateTo` call:

```cs
await LocalStorage.SetAsync(JSRuntime, "currentorder", OrderState.Order);
```

You'll learn much more about JavaScript interop in later part of this workshop, so you don't need to get too deep into this right now. But if you want, have a look at the implementation of `LocalStorage.cs` in `BlazingPizza.ComponentsLibrary` and `localStorage.js` - there's not much to it.

Now you've done this, the current order state will be persisted in JSON form in `localStorage` right before the redirection occurs. You can see the data using the browser's JavaScript console after executing this code path:

![image](https://user-images.githubusercontent.com/1101362/59276103-90258e80-8c55-11e9-9489-5625f424880f.png)

This is still not quite enough, because even though you're saving the data, you're not yet reloading it when the user returns to the app. Add the following logic at the bottom of `OnInitializedAsync` in `Checkout.razor`:

```cs
// Try to recover any temporary saved order
if (!OrderState.Order.Pizzas.Any())
{
    var savedOrder = await LocalStorage.GetAsync<Order>(JSRuntime, "currentorder");
    if (savedOrder != null)
    {
        OrderState.ReplaceOrder(savedOrder);
        await LocalStorage.DeleteAsync(JSRuntime, "currentorder");
    }
    else
    {
        // There's nothing check out - go to home
        NavigationManager.NavigateTo("");
    }
}
```

You'll also need to add the following method to `OrderState` to accept the loaded order:

```cs
public void ReplaceOrder(Order order)
{
    Order = order;
}
```

Now you should no longer be able to reproduce the "lost order state" bug. Your order should be preserved across the redirection flow.

## Handling signed-out users on "My orders"

If you're signed out and visit "My orders", the server will reject the request to `/orders`, causing a client-side exception (try it and see). To avoid this, we should change the UI so that it displays a notice about needing to log in instead. How should we do this?

There are three basic ways to interact with the authentication/authorization system inside components. We've already seen two of them:

 * You can use `<AuthorizeView>`. This is useful when you just need to vary some UI content according to authorization status.
 * You can use a `[CascadingParameter]` to receive a `Task<AuthenticationState>`. This is useful when you want to use the `AuthenticationState` in procedural logic such as an event handler.

The third way, which we'll use here, is:

 * You can place an `[Authorize]` attribute on a routable `@page` component. This is useful if you want to control the reachability of an entire page based on authorization conditions.

So, go to `MyOrders`, and and put the following directive at the top (just under the `@page` line):

```cs
@attribute [Authorize]
```

The `[Authorize]` functionality is part of the routing system, and we'll need to make some changes there. In `App.razor`, replace `<RouteView ../>` with `<AuthorizeRouteView .../>`.

```html
<CascadingAuthenticationState>
    <Router AppAssembly="typeof(Program).Assembly" Context="routeData">
        <Found>
            <AuthorizeRouteView RouteData="routeData" DefaultLayout="typeof(MainLayout)" />
        </Found>
        ...
    </Router>
</CascadingAuthenticationState>
```

The `AuthorizeRouteView` component is like `RouteView` in that it can display a routable component and it's layout, but also integrates with `[Authorize]`.

---

Now, logged in users can reach the *My orders* page, but logged out users will see the message *Not authorized* instead. Verify you can see this working.

Finally, let's be a bit friendlier to logged out users. Instead of just saying *Not authorized*, we can customize this to display a link to sign in. Go to `App.razor`, and pass the following `<NotAuthorized>` and `<Authorizing>` parameters to the `<AuthorizeRouteView>`:

```html
<AuthorizeRouteView RouteData="routeData" DefaultLayout="typeof(MainLayout)">
    <NotAuthorized>
        <div class="main">
            <h2>You're signed out</h2>
            <p>To continue, please sign in.</p>
            <a class="btn btn-danger" href="user/signin">Sign in</a>
        </div>
    </NotAuthorized>
    <Authorizing>
        <div class="main">Please wait...</div>
    </Authorizing>
</AuthorizeRouteView>
```

Now if you're logged out and try to go to *My orders*, you'll get a much nicer outcome:

![image](https://user-images.githubusercontent.com/1101362/51807840-11225180-2284-11e9-81ed-ea9caacb79ef.png)

## Handling signed-out users on "Order details"

If you directly browse to `/myorders/1` while signed out, you'll get a strange message:

![image](https://user-images.githubusercontent.com/1101362/51807869-5f375500-2284-11e9-8417-dcd572cd028d.png)

Once again, this is because the server is rejecting the query for order details while signed out.

But you can fix this trivially: just use `[Authorize]` on `OrderDetails.razor` in the same way you did on `MyOrders.razor`. Try it out! It will display the same "please sign in" prompt to unauthenticated visitors.

## Authorizing access to specific order details

Although the server requires authentication before accepting queries for order information, it still doesn't distinguish between users. All signed-in users can see the orders from all other signed-in users. We have authentication, but no authorization!

To verify this, place an order while signed in with one Twitter account. Then sign out and back in using a different Twitter account. You'll still be able to see the same order details.

This is easily fixed. Back in the `OrdersController` code, look for the commented-out line in `PlaceOrder`, and uncomment it:

```cs
order.UserId = GetUserId();
```

Now each order will be stamped with the ID of the user who owns it.

Next look for the commented-out `.Where` lines in `GetOrders` and `GetOrderWithStatus`, and uncomment both. These lines ensure that users can only retrieve details of their own orders:

```csharp
.Where(o => o.UserId == GetUserId())
```

Now if you run the app again, you'll no longer be able to see the existing order details, because they aren't associated with your user ID. If you place a new order with one Twitter account, you won't be able to see it from a different Twitter account. That makes the application much more useful.

Next up - [JavaScript interop](07-javascript-interop.md)

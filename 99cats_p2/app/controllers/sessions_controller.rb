class SessionsController < ApplicationController
    def new
        render :new
    end

    def create
        @user = User.find_by_credentials(params[:user][:username], params[:user][:password])
        debugger
        if @user
            login!(@user)
            redirect_to cats_url
        else
            render :new
        end
    end

    def destroy
        logout
    end
end
